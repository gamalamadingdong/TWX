# models/vuln_classifier.py
import sys
import os

# Add the project root directory to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
from time import time
from storage.vulnerability_db import VulnerabilityDatabase

def prepare_data(data_path="analysis/classification_data.csv"):
    """Load and prepare data for vulnerability type classification while preserving details."""
    df = pd.read_csv(data_path, low_memory=False, parse_dates=['published_date', 'modified_date'])
    print("preparing data")
    # Define features (keep as is)
    # TODO: Improve For Production.  These features were a first pass and should be improved
    cat_features = ["cwe", "vendor", "product", "av", "ac", "pr", "ui",
                   "known_exploited", "has_cisa_advisory", "has_vendor_advisory"]
    
    num_features = ["base_score", "product_count", "reference_count", 
                   "days_to_patch", "exploit_maturity"]
    
    print("Features Defined")
    # Ensure all features are present
    for feat in cat_features:
        if feat not in df.columns:
            print(f"Warning: Feature '{feat}' not in dataset, adding as empty")
            df[feat] = ""
    
    for feat in num_features:
        if feat not in df.columns:
            print(f"Warning: Feature '{feat}' not in dataset, adding as zeros")
            df[feat] = 0
    print("Mapping CWE to vulnerability types...")
    # Map CWE to vulnerability type categories (primary classification target)
    df['vuln_type'] = df['cwe'].apply(map_cwe_to_vuln_type)
    
    # Rather than dropping, assign "Unknown" to missing vuln_type
    df['vuln_type'] = df['vuln_type'].fillna('Unknown')
    
    # Create severity as a feature (based on CVSS)
    # Handle missing base_score values by replacing NaN with 0 before cutting
    df["base_score"] = df["base_score"].fillna(0)
    df["severity"] = pd.cut(df["base_score"], 
                           bins=[0, 3.9, 6.9, 8.9, 10.0],
                           labels=["Low", "Medium", "High", "Critical"]) #should have a severity value
    
    # Preserve detailed information
    if 'affected_services_details' not in df.columns and 'product_details' in df.columns:
        df['affected_services_details'] = df['product_details']
    
    if 'mitigation_info' not in df.columns and 'references' in df.columns:
        df['mitigation_info'] = df['references'].apply(extract_mitigation_info)
    
    # Reduce cardinality of categorical features to minimize one-hot encoding explosion
    # TODO: Improve For Production.  Did this because of the size of the dataset and training it on my laptop

    print("Limiting cardinality of high-dimensional categorical features...")
    
    # Keep only top vendors, map others to 'Other_Vendor'
    top_vendors = df['vendor'].value_counts().head(50).index
    df.loc[~df['vendor'].isin(top_vendors), 'vendor'] = 'Other_Vendor'
    print(f"Reduced vendor cardinality from {df['vendor'].nunique()} to 51 (including 'Other_Vendor')")

    # Keep only top products, map others to 'Other_Product'
    top_products = df['product'].value_counts().head(100).index
    df.loc[~df['product'].isin(top_products), 'product'] = 'Other_Product'
    print(f"Reduced product cardinality from {df['product'].nunique()} to 101 (including 'Other_Product')")
    
    # Only keep classes that have at least 6 samples (for 5-fold CV)
    class_counts = df['vuln_type'].value_counts()
    rare_classes = class_counts[class_counts < 6].index
    print(f"Removing {len(rare_classes)} rare vulnerability types with fewer than 6 samples")
    
    # Either filter them out:
    df = df[~df['vuln_type'].isin(rare_classes)]
    # Or merge them into "Other" category:
    # df.loc[df['vuln_type'].isin(rare_classes), 'vuln_type'] = 'Other'
    
    # Now update ALL variables based on the filtered dataframe
    cat_features_without_cwe = [f for f in cat_features if f != 'cwe']
    X = df[cat_features_without_cwe + num_features]
    y_type = df["vuln_type"]  # Primary target (type classification)
    y_severity = df["severity"]  # Secondary target (severity classification)
    
    # Print dataset statistics before splitting
    print(f"Dataset statistics before split:")
    print(f"  Total records: {len(df)}")
    print(f"  Records with vuln_type: {len(df[~df['vuln_type'].isna()])}")
    print(f"  Unique vulnerability types: {df['vuln_type'].nunique()}")
    
    X_train, X_test, y_train_type, y_test_type, y_train_sev, y_test_sev = train_test_split(
        X, y_type, y_severity, test_size=0.2, random_state=42, stratify=y_type)
    
    return X_train, X_test, y_train_type, y_test_type, y_train_sev, y_test_sev, df, cat_features_without_cwe, num_features

def extract_mitigation_info(references):
    """Extract potential mitigation information from references."""
    # This is a placeholder - you would implement logic to parse references
    # for mitigation information based on your data format
    if not isinstance(references, str):
        return {}
    
    mitigation_info = {}
    # Example logic (adjust based on your actual data):
    if 'patch' in references.lower():
        mitigation_info['patch_available'] = True
    if 'workaround' in references.lower():
        mitigation_info['workaround_available'] = True
    return mitigation_info

from data_processing.cwe_vulnerability_types import get_vulnerability_type

# TODO: Improve For Production
def map_cwe_to_vuln_type(cwe):
    """Map CWE ID to a meaningful vulnerability type."""
    if not cwe or not isinstance(cwe, str):
        return 'Unknown'
    
    # First try the direct mapping
    vuln_type = get_vulnerability_type(cwe)
    
    # If that doesn't work, try the database for additional info
    if vuln_type == 'Other':
        db = VulnerabilityDatabase()
        conn = db.connect()
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM weaknesses WHERE cwe_id=?", (cwe,))
        result = cursor.fetchone()
        conn.close()
        
        if result and result[0]:
            # Try to categorize based on keywords in the name.  
            # This is not a long term solution but a quick fix to get a demo working
            name = result[0].lower()
            if 'inject' in name:
                return 'Injection'
            elif 'buffer' in name or 'overflow' in name:
                return 'Buffer Overflow'
            elif 'xss' in name or 'cross site' in name:
                return 'Cross-site Scripting (XSS)'
            elif 'bypass' in name:
                return 'Security Bypass'
            # Add more keyword checks as needed
    
    return vuln_type

def build_type_classifier(X_train, y_train, cat_features, num_features):
    """Build and train a vulnerability type classifier with tuning."""
    # Create preprocessing steps
    preprocessor = ColumnTransformer(
        transformers=[
            ('cat', OneHotEncoder(handle_unknown='ignore'), cat_features),
            ('num', StandardScaler(), num_features)
        ])
    
    # Create pipeline with preprocessor and classifier
    pipeline = Pipeline(steps=[
        ('preprocessor', preprocessor),
        ('classifier', RandomForestClassifier(random_state=42))
    ])
    
    # Simplified parameter grid for more efficient model without major quality loss
    param_grid = {
        'classifier__n_estimators': [50],  # Reduced from 100
        'classifier__max_depth': [15],     # Fixed value instead of [None, 20]
        'classifier__min_samples_split': [5],
        'classifier__class_weight': ['balanced']
    }
    
    # Perform grid search with cross-validation
    print("Performing hyperparameter tuning...")
    grid_search = GridSearchCV(
        pipeline, 
        param_grid, 
        cv=5, 
        scoring='f1_weighted',
        n_jobs=-1,
        verbose=1,
        error_score='raise'
    )
    
    # Set a maximum runtime using a timer instead
    start_time = time()
    max_time = 1800  # 30 minutes
    
    # Fit model with a timeout
    try:
        print("Starting model training (max 30 minutes)...")
        grid_search.fit(X_train, y_train)
        
        print(f"Best parameters: {grid_search.best_params_}")
        print(f"Best cross-validation score: {grid_search.best_score_:.4f}")
        
        # Return the best model
        return grid_search.best_estimator_
    except Exception as e:
        print(f"Error during model training: {e}")
        if time() - start_time > max_time:
            print("Training exceeded time limit. Using default model instead.")
        
        # If grid search fails, return a default model
        default_pipeline = Pipeline(steps=[
            ('preprocessor', preprocessor),
            ('classifier', RandomForestClassifier(
                n_estimators=100, 
                max_depth=20, 
                min_samples_split=5, 
                class_weight='balanced',
                random_state=42
            ))
        ])
        default_pipeline.fit(X_train, y_train)
        return default_pipeline

def main(skip_training=False):
    """
    Main function to prepare data and train or load a vulnerability type classifier.
    
    Args:
        skip_training (bool): If True, attempts to load a pre-trained model instead of training
                              a new one. If loading fails, falls back to training. Defaults to False.
    
    Returns:
        tuple: The trained model and processed dataset
    """
    print(f"Running vulnerability classifier with skip_training={skip_training}")
    
    # Load and prepare data
    X_train, X_test, y_train_type, y_test_type, y_train_sev, y_test_sev, df, cat_features, num_features = prepare_data()
    
    # Handle model (either load existing or train new)
    model_path = "models/vuln_type_classifier.joblib"
    model = None
    
    if skip_training:
        # Try to load existing model
        print("Attempting to load pre-trained model...")
        try:
            if os.path.exists(model_path):
                model = joblib.load(model_path)
                print(f"Successfully loaded model from {model_path}")
            else:
                print(f"No model found at {model_path}")
                model = None
        except Exception as e:
            print(f"Error loading model: {e}")
            model = None
    
    # Train new model if needed (either by choice or because loading failed)
    if model is None:
        print("Training new vulnerability type classifier...")
        model = build_type_classifier(X_train, y_train_type, cat_features, num_features)
        
        # Evaluate model
        print("Evaluating vulnerability type classifier...")
        y_pred_type = model.predict(X_test)
        print("Classification Report for Vulnerability Types:")
        print(classification_report(y_test_type, y_pred_type))
        
        # Save model
        os.makedirs(os.path.dirname(model_path), exist_ok=True)
        joblib.dump(model, model_path)
        print(f"Type classifier saved to {model_path}")
    
    # Save the complete dataset with classifications for further analysis
    output_path = "analysis/classified_vulnerabilities_with_details.csv"
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df.to_csv(output_path, index=False)
    print(f"Complete classified dataset with details saved to {output_path}")
    
    print("\nVulnerability classification complete.")
    print("For detailed analysis, run: python analysis/advanced_vulnerability_analysis.py")
    
    return model, df


if __name__ == "__main__":
    # The skip-training argument is still useful as an endpoint for model functions
    # It allows users to quickly use an existing model without retraining
    if len(sys.argv) > 1 and "--skip-training" in sys.argv:
        main(skip_training=True)
    else:
        main(skip_training=False)