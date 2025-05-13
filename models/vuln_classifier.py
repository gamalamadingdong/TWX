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
from data_processing.cwe_vulnerability_types import get_vulnerability_type

def prepare_data(data_path="analysis/classification_data.csv"):
    """Load and prepare data for vulnerability type classification while preserving details."""
    df = pd.read_csv(data_path, low_memory=False, parse_dates=['published_date', 'modified_date'])
    print("preparing data")
    # Define features (keep as is)
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
                           labels=["Low", "Medium", "High", "Critical"])
    
    # Preserve detailed information
    if 'affected_services_details' not in df.columns and 'product_details' in df.columns:
        df['affected_services_details'] = df['product_details']
    
    if 'mitigation_info' not in df.columns and 'references' in df.columns:
        df['mitigation_info'] = df['references'].apply(extract_mitigation_info)
    
    # Reduce cardinality of categorical features to minimize one-hot encoding explosion
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

def analyze_services_by_vulnerability_type(df):
    """Analyze which services are most affected by each vulnerability type."""
    results = {}
    
    # For each vulnerability type
    for vuln_type in df['vuln_type'].unique():
        # Filter to just this vulnerability type
        type_df = df[df['vuln_type'] == vuln_type]
        
        # Count occurrences of each product
        service_counts = type_df['product'].value_counts().head(10)
        
        results[vuln_type] = service_counts
        
        # Generate visualization
        plt.figure(figsize=(12, 6))
        service_counts.plot(kind='bar')
        plt.title(f"Top Services Affected by {vuln_type}")
        plt.xlabel("Service")
        plt.ylabel("Count")
        plt.tight_layout()
        plt.savefig(f"analysis/services_affected_by_{vuln_type.replace(' ', '_').lower()}.png")
    
    return results

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

def map_cwe_to_vuln_type(cwe):
    """Map CWE ID to a meaningful vulnerability type category."""
    if not cwe or not isinstance(cwe, str):
        return 'Unknown'
    
    return get_vulnerability_type(cwe)

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
        # Removed: callback=TimeoutCallback(timeout=1800)
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

def analyze_vulnerability_landscape(df):
    """Analyze the vulnerability landscape including prevalence and severity."""
    # Vulnerability type distribution (prevalence)
    plt.figure(figsize=(14, 8))
    type_counts = df["vuln_type"].value_counts()
    
    # Fix for deprecation warning
    sns.barplot(y=type_counts.index, x=type_counts.values, color="steelblue")
    plt.title("Distribution of Vulnerability Types (Prevalence)")
    plt.xlabel("Count")
    plt.ylabel("Vulnerability Type")
    plt.tight_layout()
    plt.savefig("analysis/vuln_type_distribution.png")
    
    # Severity distribution within each vulnerability type
    plt.figure(figsize=(16, 10))
    crosstab = pd.crosstab(df["vuln_type"], df["severity"])
    crosstab_pct = crosstab.div(crosstab.sum(axis=1), axis=0)
    
    crosstab_pct.plot(kind="barh", stacked=True, colormap="viridis")
    plt.title("Severity Distribution by Vulnerability Type")
    plt.xlabel("Proportion")
    plt.ylabel("Vulnerability Type")
    plt.legend(title="Severity")
    plt.tight_layout()
    plt.savefig("analysis/vuln_type_severity_distribution.png")
    
    # Calculate the weighted risk score for each vulnerability type
    # This combines prevalence and severity into a single metric
    severity_weights = {
        "Low": 1,
        "Medium": 3,
        "High": 6,
        "Critical": 10
    }
    
    # Create a dataframe with type, count and weighted score
    risk_scores = []
    for vuln_type in df["vuln_type"].unique():
        type_df = df[df["vuln_type"] == vuln_type]
        count = len(type_df)
        
        # Handle missing values more robustly
        valid_severities = type_df["severity"].dropna()
        if len(valid_severities) > 0:
            # Convert to string type before mapping to avoid categorical issues
            severity_values = valid_severities.astype(str).map(severity_weights).fillna(0) 
            weighted_score = sum(severity_values) / len(valid_severities)
        else:
            weighted_score = 0
        
        risk_scores.append({
            "vuln_type": vuln_type,
            "count": count,
            "avg_severity_weight": weighted_score,
            "risk_score": count * weighted_score  # Combines prevalence and severity
        })
    
    risk_df = pd.DataFrame(risk_scores).sort_values("risk_score", ascending=False)
    
    # Plot combined risk score
    plt.figure(figsize=(14, 8))
    sns.barplot(y="vuln_type", x="risk_score", data=risk_df, color="purple")
    plt.title("Combined Risk Score by Vulnerability Type (Prevalence × Severity)")
    plt.xlabel("Risk Score")
    plt.ylabel("Vulnerability Type")
    plt.tight_layout()
    plt.savefig("analysis/vuln_type_risk_score.png")
    
    return risk_df

def main(skip_training=False):
    # IMPORTANT: Make skip_training check at the very beginning
    
    X_train, X_test, y_train_type, y_test_type, y_train_sev, y_test_sev, df, cat_features, num_features = prepare_data()
    #skip_training = True
    if skip_training == False:
        # Build vulnerability type classifier
        print("Building vulnerability type classifier...")
        type_model = build_type_classifier(X_train, y_train_type, cat_features, num_features)
        
        # Evaluate model
        print("Evaluating vulnerability type classifier...")
        y_pred_type = type_model.predict(X_test)
        print("Classification Report for Vulnerability Types:")
        print(classification_report(y_test_type, y_pred_type))
        
        # Save model
        model_path = "models/vuln_type_classifier.joblib"
        joblib.dump(type_model, model_path)
        print(f"Type classifier saved to {model_path}")
    else:
        print("Skipping training, loading existing model (if available)...")
        try:
            # Load the existing model if available
            model_path = "models/vuln_type_classifier.joblib"
            if os.path.exists(model_path):
                joblib.load(model_path)
                print(f"Loaded existing model from {model_path}")
            else:
                print(f"No existing model found at {model_path}, but continuing with analysis")
        except Exception as e:
            print(f"Error loading model: {e}, but continuing with analysis")
    
    # Analyze vulnerability landscape (prevalence and severity)
    print("Analyzing vulnerability landscape...")
    risk_df = analyze_vulnerability_landscape(df)
    print("\nTop 5 vulnerability types by combined risk score:")
    print(risk_df[["vuln_type", "count", "avg_severity_weight", "risk_score"]].head(5))
    
    # Save the complete dataset with classifications for further analysis
    output_path = "analysis/classified_vulnerabilities_with_details.csv"
    df.to_csv(output_path, index=False)
    print(f"Complete classified dataset with details saved to {output_path}")
    
    # Save the risk analysis results
    risk_df.to_csv("analysis/vulnerability_risk_analysis.csv", index=False)
    print("Risk analysis saved to analysis/vulnerability_risk_analysis.csv")


if __name__ == "__main__":
    #analyze_vulnerability_landscape
    # Check for command line arguments to skip training
    if len(sys.argv) > 1 and sys.argv[1] == "--skip-training":
        main(skip_training=True)
    else:
        main(skip_training=False)