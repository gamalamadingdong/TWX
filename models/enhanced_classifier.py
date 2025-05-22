"""
Enhanced vulnerability classification model for TWX.

This classifier combines robust NaN handling with ensemble learning and
advanced feature extraction to provide accurate vulnerability type classification.
"""

import os
import sys
import pandas as pd
import numpy as np
import joblib
import re
import json
from time import time
from sklearn.model_selection import train_test_split, GridSearchCV, StratifiedKFold
from sklearn.ensemble import RandomForestClassifier, VotingClassifier, HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import OneHotEncoder, StandardScaler, LabelEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, confusion_matrix, f1_score
from sklearn.feature_selection import SelectFromModel
from sklearn.impute import SimpleImputer
import matplotlib.pyplot as plt
import seaborn as sns

# Add the project root directory to Python path
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(root_dir)

from storage.vulnerability_db import VulnerabilityDatabase

# --- Fuzzy vulnerability type matching ---
TYPE_SYNONYMS = {
    "Buffer Overflow": {"Buffer Overflow", "Heap Overflow", "Stack Overflow", "Buffer Overrun", "Out-of-bounds Write"},
    "SQL Injection": {"SQL Injection", "SQLi", "SQL Code Injection"},
    "Cross-site Scripting (XSS)": {"Cross-site Scripting (XSS)", "XSS", "Cross Site Scripting", "Stored XSS", "Reflected XSS", "DOM-based XSS"},
    "Path Traversal": {"Path Traversal", "Directory Traversal", "File Path Traversal"},
    "Command Injection": {"Command Injection", "OS Command Injection", "Shell Injection"},
    "Deserialization": {"Deserialization", "Insecure Deserialization"},
    "Race Condition": {"Race Condition", "TOCTOU", "Time-of-check Time-of-use"},
    "Authentication Bypass": {"Authentication Bypass", "Auth Bypass", "Improper Authentication"},
    "Privilege Escalation": {"Privilege Escalation", "Elevation of Privilege", "EoP"},
    "Information Disclosure": {"Information Disclosure", "Sensitive Data Exposure", "Data Leak"},
    "Denial of Service": {"Denial of Service", "DoS", "Resource Exhaustion"},
    "Improper Input Validation": {"Improper Input Validation", "Input Validation", "Improper Validation"},
    "Cross-Site Request Forgery (CSRF)": {"Cross-Site Request Forgery (CSRF)", "CSRF"},
    "Memory Corruption": {"Memory Corruption", "Use After Free", "Dangling Pointer", "Double Free"},
    "Code Execution": {"Code Execution", "Remote Code Execution", "RCE", "Arbitrary Code Execution"},
    "Directory Listing": {"Directory Listing", "Directory Indexing"},
    "Improper Access Control": {"Improper Access Control", "Authorization Bypass", "Access Control"},
    "XML External Entity (XXE)": {"XML External Entity (XXE)", "XXE"},
    "Server-Side Request Forgery (SSRF)": {"Server-Side Request Forgery (SSRF)", "SSRF"},
    "Open Redirect": {"Open Redirect", "URL Redirection"},
    "Unrestricted File Upload": {"Unrestricted File Upload", "Arbitrary File Upload"},
    "Improper Certificate Validation": {"Improper Certificate Validation", "SSL Validation", "TLS Validation"},
    "Improper Error Handling": {"Improper Error Handling", "Information Exposure Through Error Message"},
    "Improper Authorization": {"Improper Authorization", "Authorization Bypass"},
    "Improper Resource Shutdown or Release": {"Improper Resource Shutdown or Release", "Resource Leak"},
    # Add more as needed
}

def fuzzy_type_match(predicted, validated):
    """
    Returns True if predicted and validated types are considered a fuzzy match.
    """
    if not predicted or not validated:
        return False
    predicted = predicted.strip()
    validated = validated.strip()
    # Exact match
    if predicted == validated:
        return True
    # Synonym/alias match
    for synonyms in TYPE_SYNONYMS.values():
        if predicted in synonyms and validated in synonyms:
            return True
    # Partial string match (case-insensitive)
    if predicted.lower() in validated.lower() or validated.lower() in predicted.lower():
        return True
    return False

# Add this class at the module level (before any function definitions)
class ModelWrapper:
    """
    Wrapper class for simple models with custom preprocessing.
    Used as a fallback when more sophisticated models fail.
    """
    def __init__(self, model, cat_encoder, cat_features, num_features):
        self.model = model
        self.cat_encoder = cat_encoder
        self.cat_features = cat_features
        self.num_features = num_features
    
    def predict(self, X):
        if len(self.cat_features) > 0:
            cat_data = X[self.cat_features].fillna('MISSING')
            encoded_cats = self.cat_encoder.transform(cat_data)
            num_data = X[self.num_features].fillna(0).values
            X_combined = np.hstack([encoded_cats, num_data])
        else:
            X_combined = X[self.num_features].fillna(0).values
        return self.model.predict(X_combined)
    
    def predict_proba(self, X):
        if len(self.cat_features) > 0:
            cat_data = X[self.cat_features].fillna('MISSING')
            encoded_cats = self.cat_encoder.transform(cat_data)
            num_data = X[self.num_features].fillna(0).values
            X_combined = np.hstack([encoded_cats, num_data])
        else:
            X_combined = X[self.num_features].fillna(0).values
        return self.model.predict_proba(X_combined)

def analyze_dataset_metadata(data_path):
    """Analyze dataset metadata to understand available fields and data quality."""
    # First check if we have JSON metadata
    if data_path.lower().endswith('.json'):
        metadata_path = data_path.replace('.json', '_metadata.json')
        if os.path.exists(metadata_path):
            try:
                with open(metadata_path, 'r') as f:
                    metadata = json.load(f)
                print("Dataset metadata:")
                print(f"  Export date: {metadata.get('export_date')}")
                print(f"  Record count: {metadata.get('record_count')}")
                print(f"  TWX version: {metadata.get('twx_version')}")
                print(f"  Available fields: {len(metadata.get('fields', []))} fields")
                return metadata
            except Exception as e:
                print(f"Error reading metadata: {e}")
    
    # If no metadata file or it's CSV, analyze the actual data
    if data_path.lower().endswith('.json'):
        df = pd.read_json(data_path, orient='records')
    else:
        df = pd.read_csv(data_path, low_memory=False)
    
    print("Dataset statistics:")
    print(f"  Records: {len(df)}")
    print(f"  Columns: {len(df.columns)}")
    print(f"  Date range: {df['published'].min()} to {df['published'].max()}")
    
    # Check for important columns
    key_cols = ['vuln_id', 'description', 'primary_cwe', 'vuln_type', 
                'vendors', 'products', 'patch_date', 'days_to_patch']
    missing = [col for col in key_cols if col not in df.columns]
    if missing:
        print(f"  WARNING: Missing key columns: {missing}")
    
    return {
        "record_count": len(df),
        "fields": list(df.columns),
        "missing_fields": missing
    }

def load_validation_data(validation_file="models/validation_sample.csv"):
    """
    Load the manually validated vulnerability data.
    
    Args:
        validation_file: Path to the validation CSV file
        
    Returns:
        DataFrame containing validation data
    """
    try:
        validation_df = pd.read_csv(validation_file, low_memory=False)
        print(f"Loaded {len(validation_df)} manually validated records")
        
        # Check if validation data has the required column
        if 'validated_type' not in validation_df.columns:
            print(f"Warning: 'validated_type' column missing from validation data")
            return None
            
        # Check how many records have validated types
        valid_count = validation_df['validated_type'].notnull().sum()
        print(f"Found {valid_count} records with validated vulnerability types")
        
        return validation_df
    except Exception as e:
        print(f"Error loading validation data: {e}")
        return None

def map_cwe_to_vuln_type(cwe):
    """
    Map CWE ID to a meaningful vulnerability type with improved accuracy.
    Leverages both CWE mapping and validation data patterns.
    """
    if not cwe or not isinstance(cwe, str):
        return 'Unknown'
    
    # Direct mapping from CWE to vulnerability type
    vuln_type = get_vulnerability_type(cwe)
    
    # If that doesn't yield a specific type, try the database for more context
    if vuln_type == 'Other':
        try:
            db = VulnerabilityDatabase()
            conn = db.connect()
            cursor = conn.cursor()
            cursor.execute("SELECT name, description FROM weaknesses WHERE cwe_id=?", (cwe,))
            result = cursor.fetchone()
            conn.close()
            
            if result and result[0]:
                name = result[0].lower()
                description = result[1].lower() if result[1] else ""
                
                # Enhanced categorization using both name and description
                text_to_analyze = name + " " + description
                
                # Improved mapping logic with more specific patterns
                type_patterns = {
                    'Injection': ['inject', 'sql', 'command', 'ldap', 'xpath', 'nosql'],
                    'Cross-site Scripting (XSS)': ['xss', 'cross site', 'script', 'client side'],
                    'Buffer Overflow': ['buffer', 'overflow', 'out of bounds', 'stack', 'heap'],
                    'Information Disclosure': ['info', 'disclos', 'leak', 'expose', 'sensitive'],
                    'Denial of Service (DoS)': ['dos', 'denial', 'crash', 'resource', 'exhaust'],
                    'Authentication Issues': ['authent', 'login', 'password', 'credential'],
                    'Authorization Issues': ['authoriz', 'access control', 'permission'],
                    'Cryptographic Issues': ['crypto', 'cipher', 'encrypt', 'random', 'hash'],
                    'Path Traversal': ['path', 'travers', 'directory', 'file include'],
                    'Race Condition': ['race', 'toctou', 'synchron', 'concurr'],
                    'Memory Corruption': ['memory', 'corrupt', 'use after free', 'double free'],
                    'Input Validation': ['input', 'valid', 'sanitiz', 'filter'],
                    'CSRF': ['csrf', 'cross site request', 'forgery'],
                    'Security Bypass': ['bypass', 'circumvent', 'disable'],
                    'Privilege Escalation': ['privilege', 'escal', 'elevation']
                }
                
                # Check each pattern set
                for type_name, patterns in type_patterns.items():
                    if any(pattern in text_to_analyze for pattern in patterns):
                        return type_name
        except Exception as e:
            print(f"Error querying CWE database: {e}")
    
    return vuln_type

def get_vulnerability_type(cwe):
    """
    Enhanced function to map CWE to vulnerability type.
    Incorporates manual validation patterns.
    """
    # Common CWEs mapped to vulnerability types
    cwe_mapping = {
        # Injection vulnerabilities
        'CWE-89': 'SQL Injection',
        'CWE-564': 'SQL Injection',
        'CWE-79': 'Cross-site Scripting (XSS)',
        'CWE-80': 'Cross-site Scripting (XSS)',
        'CWE-78': 'Command Injection',
        'CWE-77': 'Command Injection',
        'CWE-91': 'XML Injection',
        'CWE-917': 'Expression Language Injection',
        
        # Authentication/Access
        'CWE-287': 'Authentication Issues',
        'CWE-306': 'Authentication Issues',
        'CWE-522': 'Weak Credentials',
        'CWE-521': 'Weak Credentials',
        'CWE-798': 'Hardcoded Credentials',
        'CWE-259': 'Hardcoded Credentials',
        'CWE-284': 'Access Control Issues',
        'CWE-285': 'Access Control Issues',
        'CWE-639': 'Access Control Issues',

        # Information disclosure
        'CWE-200': 'Information Disclosure',
        'CWE-209': 'Information Disclosure',
        'CWE-532': 'Information Disclosure',
        
        # File-related vulnerabilities
        'CWE-22': 'Path Traversal',
        'CWE-23': 'Path Traversal',
        'CWE-434': 'Unrestricted File Upload',
        'CWE-73': 'Path Traversal',
        'CWE-59': 'Link Following',
        
        # Memory safety
        'CWE-119': 'Buffer Overflow',
        'CWE-120': 'Buffer Overflow',
        'CWE-121': 'Stack-based Buffer Overflow',
        'CWE-122': 'Heap-based Buffer Overflow',
        'CWE-125': 'Out-of-bounds Read',
        'CWE-787': 'Out-of-bounds Write',
        'CWE-416': 'Use After Free',
        'CWE-415': 'Double Free',
        'CWE-476': 'NULL Pointer Dereference',
        'CWE-401': 'Memory Leak',
        'CWE-400': 'Resource Exhaustion',
        'CWE-674': 'Resource Exhaustion',
        
        # Cryptographic
        'CWE-295': 'Certificate Validation',
        'CWE-327': 'Broken/Risky Crypto',
        'CWE-328': 'Broken/Risky Crypto',
        'CWE-326': 'Inadequate Encryption Strength',
        'CWE-759': 'Weak Salt',
        'CWE-321': 'Broken/Risky Crypto',
        
        # Web-specific
        'CWE-352': 'Cross-Site Request Forgery (CSRF)',
        'CWE-601': 'Open Redirect',
        'CWE-918': 'SSRF',
        'CWE-611': 'XXE',
        'CWE-384': 'Session Fixation',
        
        # Other
        'CWE-20': 'Improper Input Validation',
        'CWE-94': 'Code Injection',
        'CWE-502': 'Deserialization of Untrusted Data',
        'CWE-269': 'Privilege Escalation',
        'CWE-863': 'Access Control Issues',
        'CWE-770': 'Resource Allocation',
        'CWE-362': 'Race Condition',
        'CWE-319': 'Cleartext Transmission',
        'CWE-330': 'Weak Random',
    }
    
    # Normalize CWE format
    if isinstance(cwe, str):
        if cwe.isdigit():
            cwe_id = f"CWE-{cwe}"
        elif cwe.lower().startswith('cwe-') and cwe[4:].isdigit():
            cwe_id = f"CWE-{cwe[4:]}"
        else:
            cwe_id = cwe
    else:
        return "Unknown"
    
    # Look up the vulnerability type
    return cwe_mapping.get(cwe_id, "Other")

def extract_cwe_group(cwe_str):
    """Extract CWE group for better feature grouping."""
    if not isinstance(cwe_str, str) or not cwe_str.strip():
        return 'Unknown'
    
    # Extract CWE number
    match = re.search(r'CWE-(\d+)', cwe_str)
    if not match:
        try:
            # Try to extract just the number
            if cwe_str.isdigit():
                cwe_num = int(cwe_str)
            else:
                return 'Other'
        except:
            return 'Other'
    else:
        cwe_num = int(match.group(1))
    
    # Group by hundreds (e.g., CWE-79 -> CWE-0xx)
    return f"CWE-{cwe_num // 100}xx"

def extract_text_features(df):
    """Extract features from text descriptions."""
    # Add basic text features
    if 'description' in df.columns:
        # Length of description might correlate with complexity
        df['description_length'] = df['description'].fillna('').apply(len)
        
        # Count of technical terms might indicate vulnerability type
        tech_terms = ['buffer', 'overflow', 'injection', 'XSS', 'SQL', 'authentication',
                     'authorization', 'privilege', 'memory', 'leak', 'disclosure']
        
        for term in tech_terms:
            df[f'has_{term.lower()}'] = df['description'].fillna('').str.lower().str.contains(term.lower()).astype(int)
    
    return df

def prepare_enhanced_data(data_path, validation_file=None, include_text=True, filter_unknown=False):
    """
    Load and prepare data for vulnerability type classification with robust NaN handling
    and enhanced feature extraction.
    
    Args:
        data_path: Path to the main dataset CSV
        validation_file: Path to validation data CSV
        include_text: Whether to include text features
        filter_unknown: Whether to filter out "Unknown" or "Other" vulnerability types
        
    Returns:
        X, y, and feature information
    """
    print(f"Loading data from {data_path}")
    if data_path.lower().endswith('.json'):
    # Load JSON data
        df = pd.read_json(data_path, orient='records')
        print(f"Loaded {len(df)} records from JSON")
    else:
        # Fall back to CSV for compatibility
        df = pd.read_csv(data_path, low_memory=False, parse_dates=['published', 'modified'])
        print(f"Loaded {len(df)} records from CSV")  
    # Check for NaN values in the dataset before processing
    nan_counts = df.isna().sum()
    print("NaN counts before preprocessing:")
    for col, count in nan_counts[nan_counts > 0].items():
        print(f"  {col}: {count} ({count/len(df)*100:.1f}%)")
    
    # Load validation data if provided
    validation_df = None
    if validation_file:
        validation_df = load_validation_data(validation_file)
    
    # Define feature groups
    cat_features = [
        "cwe", "cwe_name", "cwe_category",  # CWE details
        "vendor", "product",                # Target information
        "av", "ac", "pr", "ui", "s", "c", "i", "a",  # CVSS vector components
        "known_exploited", "has_cisa_advisory", "has_vendor_advisory"  # Exploit information
    ]
    
    num_features = [
        "base_score", "exploitability_score", "impact_score",  # CVSS scores
        "product_count", "reference_count",   # Scope information
        "days_to_patch", "exploit_maturity",  # Temporal information
        "epss_score", "epss_percentile"       # Exploit probability
    ]
    
    text_features = ["description"] if include_text else []
    
    # Fill missing values with appropriate defaults
    print("Filling missing values with appropriate defaults...")
    
    # Handle categorical features
    for feat in cat_features:
        if feat not in df.columns:
            print(f"  Adding missing feature '{feat}' with default value ''")
            df[feat] = ""
        else:
            missing = df[feat].isna().sum()
            if missing > 0:
                print(f"  Filling {missing} NaN values in '{feat}' with ''")
                df[feat] = df[feat].fillna("")
    
    # Handle numeric features
    for feat in num_features:
        if feat not in df.columns:
            print(f"  Adding missing feature '{feat}' with default value 0")
            df[feat] = 0
        else:
            missing = df[feat].isna().sum()
            if missing > 0:
                print(f"  Filling {missing} NaN values in '{feat}' with 0")
                df[feat] = df[feat].fillna(0)
    
    # Handle description text feature
    for feat in text_features:
        if feat in df.columns:
            missing = df[feat].isna().sum()
            if missing > 0:
                print(f"  Filling {missing} NaN values in '{feat}' with ''")
                df[feat] = df[feat].fillna("")
    
    # Drop features with high missingness
    missing_threshold = 0.8
    for col in df.columns:
        if df[col].isna().mean() > missing_threshold:
            print(f"Dropping feature '{col}' due to high missingness ({df[col].isna().mean()*100:.1f}%)")
            df = df.drop(columns=[col])
    
    # Map CWE to vulnerability types if needed
    if 'vuln_type' not in df.columns:
        print("Mapping CWE to vulnerability types...")
        df['vuln_type'] = df['cwe'].apply(map_cwe_to_vuln_type)
    else:
        print("Using existing vulnerability type classifications")
    
    # Save original vulnerability type if needed later
    if 'original_type' not in df.columns:
        df['original_type'] = df['vuln_type'].copy()
    
    # Integrate validation data if available
    if validation_df is not None:
        print("Integrating manually validated vulnerability types...")
        # Create a mapping from CVE to validated type
        valid_types = validation_df[['CVE', 'validated_type']].dropna(subset=['validated_type'])
        cve_to_type = dict(zip(valid_types['CVE'], valid_types['validated_type']))
        
        # Count how many records will be updated
        update_count = df['CVE'].isin(cve_to_type.keys()).sum() if 'CVE' in df.columns else 0
        print(f"Updating {update_count} records with validated vulnerability types")
        
        # Update vulnerability types using validation data
        if 'CVE' in df.columns:
            # Map validated types to main dataset
            df['validated_type'] = df['CVE'].map(lambda x: cve_to_type.get(x, None))
            
            # Replace predicted types with validated types where available
            mask = df['validated_type'].notnull()
            df.loc[mask, 'vuln_type'] = df.loc[mask, 'validated_type']
            print(f"Applied {mask.sum()} validated vulnerability types to the dataset")
    
    # Add severity if not present
    if "severity" not in df.columns:
        df["severity"] = pd.cut(df["base_score"], 
                              bins=[0, 3.9, 6.9, 8.9, 10.0],
                              labels=["Low", "Medium", "High", "Critical"])
    
    # Extract text features if requested
    if include_text and text_features:
        print("Extracting text features from descriptions...")
        df = extract_text_features(df)
    
    # Reduce cardinality of high-dimensional categorical features
    print("Limiting cardinality of high-dimensional categorical features...")
    
    # Vendor and product grouping
    df['vendor'] = df['vendor'].fillna('Unknown')
    df['product'] = df['product'].fillna('Unknown')
    
    # Top vendors and products
    top_vendors = df['vendor'].value_counts().head(50).index
    df.loc[~df['vendor'].isin(top_vendors), 'vendor'] = 'Other_Vendor'
    
    top_products = df['product'].value_counts().head(100).index
    df.loc[~df['product'].isin(top_products), 'product'] = 'Other_Product'
    
    # Add CWE group feature
    if 'cwe' in df.columns:
        df['cwe_group'] = df['cwe'].fillna('Unknown').apply(lambda x: extract_cwe_group(x) if isinstance(x, str) else 'Unknown')
        cat_features.append('cwe_group')
    
    # Filter out "Unknown"/"Other" if requested
    if filter_unknown:
        mask = ~df['vuln_type'].isin(['Unknown', 'Other'])
        df = df[mask]
        print(f"Filtered out {mask.sum()} 'Unknown'/'Other' records for training.")
    
    # Filter out very rare vulnerability classes
    class_counts = df['vuln_type'].value_counts()
    min_samples_per_class = 25  # Increased from 10
    rare_classes = class_counts[class_counts < min_samples_per_class].index
    print(f"Grouping {len(rare_classes)} rare vulnerability types with fewer than {min_samples_per_class} samples into 'Other'")
    df.loc[df['vuln_type'].isin(rare_classes), 'vuln_type'] = 'Other'
    
    # Define feature categories for the enhanced classifier
    final_cat_features = []
    final_num_features = []
    final_text_features = []
    final_semantic_features = []
    
    # Organize features by type
    for col in df.columns:
        if col in ['vuln_type', 'original_type', 'validated_type', 'CVE']:
            continue  # Skip target and identifier columns
            
        if col.startswith('has_') and col not in cat_features:
            final_semantic_features.append(col)
        elif col == 'description_length':
            final_num_features.append(col)
        elif col in cat_features:
            final_cat_features.append(col)
        elif col in num_features:
            final_num_features.append(col)
    
    # Add additional text-derived features
    for col in df.columns:
        if col.startswith('txt_'):
            final_text_features.append(col)
    
    # Create feature info dictionary
    feature_info = {
        'cat_features': final_cat_features,
        'num_features': final_num_features, 
        'text_features': final_text_features,
        'semantic_features': final_semantic_features
    }
    
    # Prepare final features
    feature_columns = final_cat_features + final_num_features + final_text_features + final_semantic_features
    df['vuln_type'] = df['vuln_type'].astype(str)
    # Create final feature matrix and target
    X = df[feature_columns]
    y = df['vuln_type'].astype(str)
    
    # Final check for NaN values
    nan_cols = X.columns[X.isna().any()].tolist()
    if nan_cols:
        print("WARNING: NaN values detected in feature matrix after preprocessing:")
        for col in nan_cols:
            nan_count = X[col].isna().sum()
            print(f"  {col}: {nan_count} NaN values ({nan_count/len(X)*100:.2f}%)")
        
        # Final cleanup for any remaining NaNs
        print("Applying final NaN cleanup...")
        for col in nan_cols:
            if col in final_cat_features:
                X[col] = X[col].fillna("")
            else:
                X[col] = X[col].fillna(0)
    else:
        print("No NaN values detected in feature matrix. Data is ready for training.")
    
    # Print dataset statistics
    print(f"\nDataset statistics:")
    print(f"  Total records: {len(df)}")
    print(f"  Unique vulnerability types: {df['vuln_type'].nunique()}")
    print(f"  Features: {len(feature_columns)} total ({len(final_cat_features)} categorical, "
          f"{len(final_num_features)} numerical, {len(final_text_features)} text, "
          f"{len(final_semantic_features)} semantic)")
    
    print("  Top vulnerability types:")
    for vuln_type, count in df['vuln_type'].value_counts().head(10).items():
        print(f"    {vuln_type}: {count} ({count/len(df)*100:.1f}%)")
    
    return X, y, feature_info, df

def build_enhanced_classifier(X_train, y_train, feature_info):
    """
    Build and train an enhanced vulnerability type classifier with robust error handling.
    
    Args:
        X_train: Training feature matrix
        y_train: Training target variable
        feature_info: Dictionary with feature type information
        
    Returns:
        Trained classification pipeline
    """
    # Final verification for NaN values
    nan_check = X_train.isna().sum().sum()
    if nan_check > 0:
        print(f"WARNING: {nan_check} NaN values found in training data before preprocessing!")
        print("Applying emergency NaN handling...")
        
        # Apply emergency cleaning to ensure no NaN values remain
        for col in X_train.columns:
            if X_train[col].isna().any():
                if col in feature_info['cat_features']:
                    print(f"  Filling NaNs in '{col}' with ''")
                    X_train[col] = X_train[col].fillna("")
                else:
                    print(f"  Filling NaNs in '{col}' with 0")
                    X_train[col] = X_train[col].fillna(0)
                    
        # Verify fix
        if X_train.isna().sum().sum() > 0:
            raise ValueError("Failed to remove all NaN values from training data!")
    
    # Define preprocessing for each feature type
    print("Setting up preprocessing pipelines...")
    preprocessor_steps = []
    
    # Categorical features
    if feature_info['cat_features']:
        print(f"Adding categorical transformer for {len(feature_info['cat_features'])} features")
        cat_transformer = Pipeline(steps=[
            ('imputer', SimpleImputer(strategy='constant', fill_value='')),
            ('encoder', OneHotEncoder(handle_unknown='ignore', sparse_output=False)),
        ])
        preprocessor_steps.append(('cat', cat_transformer, feature_info['cat_features']))
    
    # Numerical features
    if feature_info['num_features']:
        print(f"Adding numerical transformer for {len(feature_info['num_features'])} features")
        num_transformer = Pipeline(steps=[
            ('imputer', SimpleImputer(strategy='constant', fill_value=0)),
            ('scaler', StandardScaler())
        ])
        preprocessor_steps.append(('num', num_transformer, feature_info['num_features']))
    
    # Text features
    if feature_info['text_features']:
        print(f"Adding text transformer for {len(feature_info['text_features'])} features")
        text_transformer = Pipeline(steps=[
            ('imputer', SimpleImputer(strategy='constant', fill_value=0)),
            ('scaler', StandardScaler())
        ])
        preprocessor_steps.append(('txt', text_transformer, feature_info['text_features']))
    
    # Semantic features
    if feature_info['semantic_features']:
        print(f"Adding semantic transformer for {len(feature_info['semantic_features'])} features")
        semantic_transformer = Pipeline(steps=[
            ('imputer', SimpleImputer(strategy='constant', fill_value=0)),
            ('scaler', StandardScaler())
        ])
        preprocessor_steps.append(('sem', semantic_transformer, feature_info['semantic_features']))
    
    # Create preprocessor
    print("Creating column transformer...")
    preprocessor = ColumnTransformer(
        transformers=preprocessor_steps,
        remainder='drop',  # Drop any columns not explicitly included
        verbose=True,     # Add verbosity to see progress
        n_jobs=-1         # Use all available cores
    )
    
    # Set a maximum runtime for model training (reduced to 10 minutes from 30)
    start_time = time()
    max_time = 600  # 10 minutes
    
    # Check dataset size and use subsampling if too large
    #if len(X_train) > 100000:
    #    print(f"Large dataset detected ({len(X_train)} samples). Using reduced complexity approach.")
    #    # Skip the ensemble and go straight to a simpler model
    #    return _build_simple_classifier(X_train, y_train, preprocessor, feature_info)
    
    try:
        print("Building enhanced ensemble classifier...")
        
            # Create custom class weights: downweight 'Other' and 'Unknown'
        unique_classes = np.unique(y_train)

        label_encoder = LabelEncoder()
        y_train_encoded = label_encoder.fit_transform(y_train)
        class_labels = label_encoder.classes_
        #print("Unique Classes" , unique_classes)
        #print("Type of y_train[0]:", type(y_train.iloc[0]))
        class_weights = {cls: 1.0 for cls in unique_classes}
        #print ("Class weights dict:", class_weights)
        #print("Class weights dict keys:", list(class_weights.keys()))
        for low_info in ['Other', 'Unknown']:
            if low_info in class_labels:
                idx = list(class_labels).index(low_info)
                class_weights[low_info] = 0.2  # Downweight these classes

        # Define base classifiers for ensemble
        rf = RandomForestClassifier(
            n_estimators=500,  # Increased from 50
            max_depth=None,      # Increased from 10-15
            min_samples_split=5,
            class_weight='balanced',
            random_state=42,
            verbose=1,
            n_jobs=-1
        )
        
        hgb = HistGradientBoostingClassifier(
            max_iter=500,      # Increased from 50
            max_depth=30,      # Increased from 10
            learning_rate=0.05, # Slightly slower learning
            random_state=42,
            verbose=1
        )
        
        lr = LogisticRegression(
            max_iter=2000, 
            class_weight='balanced', 
            solver='saga', 
            n_jobs=-1
        )
        
        # Create voting ensemble
        ensemble = VotingClassifier(
            estimators=[
                ('rf', rf),
                ('hgb', hgb),
                ('lr', lr)
            ],
            voting='soft',    # Use soft voting for better probability averaging
            verbose=True
        )
        
        # Create pipeline with preprocessor and classifier
        pipeline = Pipeline(steps=[
            ('preprocessor', preprocessor),
            ('classifier', ensemble)
        ], verbose=True)  # Add verbosity to pipeline
        

        # Fit the model
        print("Training classification model (10 minute time limit)...")
        print("Progress updates will be shown during training.")
        
        # Use a timer to enforce the timeout
        pipeline.fit(X_train, np.array(y_train_encoded))
        training_time = time() - start_time
        print(f"Model training completed in {training_time:.1f} seconds")
        
        print("Model trained successfully!")
        return pipeline
        
    except Exception as e:
        print(f"Error during model training: {e}")
        
        if time() - start_time > max_time:
            print("Training exceeded time limit. Using fallback model.")
        
        # Go straight to the simple model
        return _build_simple_classifier(X_train, y_train, preprocessor, feature_info)

def _build_simple_classifier(X_train, y_train, preprocessor, feature_info):
    """Build a simpler classifier for large datasets or when ensemble fails."""
    print("Building simple robust classifier...")
    
    # For large datasets, potentially subsample to speed up training
    sample_size = min(len(X_train), 100000)  # Limit to at most 100k samples
    if len(X_train) > sample_size:
        print(f"Subsampling training data from {len(X_train)} to {sample_size} samples")
        # Create stratified sample
        
        X_sample, _, y_sample, _ = train_test_split(
            X_train, y_train, 
            train_size=sample_size,
            stratify=y_train,
            random_state=42
        )
    else:
        X_sample = X_train
        y_sample = y_train
        
    print(f"Training with {len(X_sample)} samples")
    
    try:
        # Use HistGradientBoostingClassifier - fast and can handle missing values
        simple_pipeline = Pipeline(steps=[
            ('preprocessor', preprocessor),
            ('classifier', HistGradientBoostingClassifier(
                max_iter=50,
                max_depth=10,
                learning_rate=0.1,
                random_state=42,
                verbose=1  # Show progress
            ))
        ], verbose=True)
        
        print("Training simple model...")
        start = time()
        simple_pipeline.fit(X_sample, y_sample)
        print(f"Simple model trained in {time() - start:.1f} seconds")
        return simple_pipeline
        
    except Exception as e:
        print(f"Simple classifier failed: {e}")
        print("Falling back to minimal preprocessing with RandomForest")
        
        # Process categorical features
        cat_features = feature_info['cat_features']
        num_features = feature_info['num_features'] + feature_info['text_features'] + feature_info['semantic_features']
        
        print("Preparing data for last-resort model...")
        cat_data = X_sample[cat_features].fillna('MISSING')
        cat_encoder = OneHotEncoder(handle_unknown='ignore', sparse_output=False)
        print("Encoding categorical features...")
        encoded_cats = cat_encoder.fit_transform(cat_data)
        
        # Process numerical features
        print("Processing numerical features...")
        num_data = X_sample[num_features].fillna(0).values
        
        # Combine features
        print("Combining feature sets...")
        X_combined = np.hstack([encoded_cats, num_data]) if len(cat_features) > 0 else num_data
        
        # Basic model with reduced parameters
        print("Training RandomForest model...")
        final_model = RandomForestClassifier(
            n_estimators=50,  # Reduced from 100 
            max_depth=10,     # Set a max depth for speed
            min_samples_split=10,
            class_weight='balanced',
            random_state=42,
            n_jobs=-1,       # Use all cores
            verbose=1        # Show progress
        )
        
        start = time()
        final_model.fit(X_combined, y_sample)
        print(f"Last resort model trained in {time() - start:.1f} seconds")
        
        return ModelWrapper(final_model, cat_encoder, cat_features, num_features)
def evaluate_model(model, X_test, y_test, output_dir="models"):
    """Evaluate model and generate detailed performance metrics."""
    print("Evaluating model performance...")
    y_pred = model.predict(X_test)
    #if hasattr(model, 'label_encoder'):
    #    y_pred = model.label_encoder.inverse_transform(y_pred)

    # Calculate and print metrics
    print("\nClassification Report:")
    report = classification_report(y_test, y_pred)
    print(report)
    
    # Generate confusion matrix
    plt.figure(figsize=(14, 12))
    cm = confusion_matrix(y_test, y_pred, normalize='true')
    
    # Get unique classes for consistent ordering
    classes = sorted(np.unique(np.concatenate([y_test, y_pred])))
    
    # Plot confusion matrix
    sns.heatmap(cm, annot=True, fmt='.2f', cmap='Blues',
                xticklabels=classes,
                yticklabels=classes)
    plt.xlabel('Predicted')
    plt.ylabel('True')
    plt.title('Normalized Confusion Matrix')
    plt.tight_layout()
    
    # Save the confusion matrix
    os.makedirs(output_dir, exist_ok=True)
    plt.savefig(f"{output_dir}/confusion_matrix.png")
    plt.close()
    
    # Calculate overall metrics
    f1 = f1_score(y_test, y_pred, average='weighted')
    accuracy = (y_pred == y_test).mean()
    
    metrics = {
        'f1_score': f1,
        'accuracy': accuracy
    }
    
    print(f"Overall metrics: F1 = {f1:.4f}, Accuracy = {accuracy:.4f}")
    
    return report, cm, metrics

def evaluate_on_validation(model, data_path, output_dir="models"):
    """
    Evaluate model and generate detailed performance metrics using fuzzy type matching.
    Includes debugging checks for label and feature alignment.
    """
    try:
        val_df = pd.read_csv(data_path)
        # Use validated_type where available, otherwise use vuln_type
        if 'vuln_type' in val_df.columns:
            val_df['final_type'] = val_df['validated_type'].fillna(val_df['vuln_type'])
        else:
            val_df = val_df.dropna(subset=['validated_type'])
            val_df['final_type'] = val_df['validated_type']

        # Prepare features and labels
        X_val, y_val, _, _ = prepare_enhanced_data(data_path)
        y_pred = model.predict(X_val)

        # --- Debugging checks ---
        print("\n--- DEBUGGING LABELS AND FEATURES ---")
        print("Sample of predicted vs. true labels (first 20):")
        for pred, true in list(zip(y_pred, y_val))[:20]:
            print(f"Predicted: {pred} | True: {true}")

        print("\nUnique predicted types:", sorted(set(y_pred)))
        print("Unique true types:", sorted(set(y_val)))
        print("Value counts for true types:\n", pd.Series(y_val).value_counts())
        print("Value counts for predicted types:\n", pd.Series(y_pred).value_counts())
        print("Validation feature columns:", list(X_val.columns))

        # Fuzzy matching evaluation
        fuzzy_matches = [fuzzy_type_match(pred, true) for pred, true in zip(y_pred, y_val)]
        fuzzy_accuracy = np.mean(fuzzy_matches)
        print(f"\nFuzzy Accuracy (synonyms/close matches allowed): {fuzzy_accuracy:.3f}")

        # Standard report for reference
        print("\nValidation Set Classification Report (strict):")
        print(classification_report(y_val, y_pred))

        # Confusion matrix
        plt.figure(figsize=(14, 12))
        cm = confusion_matrix(y_val, y_pred, normalize='true')
        classes = sorted(np.unique(np.concatenate([y_val, y_pred])))
        sns.heatmap(cm, annot=True, fmt='.2f', cmap='Blues',
                    xticklabels=classes,
                    yticklabels=classes)
        plt.xlabel('Predicted')
        plt.ylabel('True')
        plt.title('Validation Set - Normalized Confusion Matrix')
        plt.tight_layout()
        os.makedirs(output_dir, exist_ok=True)
        plt.savefig(f"{output_dir}/validation_confusion_matrix.png")
        plt.close()

        return {"fuzzy_accuracy": fuzzy_accuracy}, cm

    except Exception as e:
        print(f"Error evaluating on validation data: {e}")
        return None, None

def main():
    """Main function to train and evaluate the enhanced classifier."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Train enhanced vulnerability classifier')
    parser.add_argument('--train', type=str, default="analysis/classification_data.json",
                    help='Path to training data (JSON or CSV)')
    parser.add_argument('--validate', type=str, default=None, 
                        help='Path to validation data CSV (with manual labels)')
    parser.add_argument('--output', type=str, default="models/enhanced_vuln_classifier.joblib",
                        help='Path to save the trained model')
    parser.add_argument('--no-text', action='store_true', 
                        help='Disable text feature extraction')
    parser.add_argument('--val-file', type=str, default="models/validation_sample.csv",
                       help='Path to validation data CSV for integrating validated types')
    parser.add_argument('--skip-training', action='store_true',
                       help='Skip training and load existing model')
    parser.add_argument('--max-samples', type=int, default=200000,
                       help='Maximum number of samples to use for training')
    parser.add_argument('--fast', action='store_true',
                       help='Use fast mode with minimal processing')
    
    args = parser.parse_args()
    
    # Handle model (either load existing or train new)
    model = None
    if args.skip_training:
        # Try to load existing model
        print("Attempting to load pre-trained model...")
        try:
            if os.path.exists(args.output):
                model = joblib.load(args.output)
                print(f"Successfully loaded model from {args.output}")
            else:
                print(f"No model found at {args.output}")
                model = None
        except Exception as e:
            print(f"Error loading model: {e}")
            model = None
    
    if model is None:
        # Prepare data with validation integration
        print(f"Loading and preparing data from {args.train}...")
        X, y, feature_info, df = prepare_enhanced_data(
            args.train, 
            validation_file=args.val_file,
            include_text=not args.no_text
        )
        
        # Check if dataset is very large and we should sample
        if len(X) > args.max_samples:
            print(f"Dataset is very large ({len(X)} samples). Subsampling to {args.max_samples} samples...")
            X_sample, _, y_sample, _ = train_test_split(
                X, y, 
                train_size=args.max_samples,
                stratify=y,
                random_state=42
            )
            X = X_sample
            y = y_sample
            print(f"Subsampled to {len(X)} training samples")
        
        # Split data for training/testing
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y)
        
        # Build and train model
        print(f"\nBuilding and training model with {len(X_train)} samples...")
        start_time = time()
        
        if args.fast:
            # Use simpler preprocessing and model for fast results
            print("Using FAST mode with simplified model...")
            from sklearn.pipeline import Pipeline
            from sklearn.preprocessing import OneHotEncoder, StandardScaler
            from sklearn.impute import SimpleImputer
            from sklearn.compose import ColumnTransformer
            from sklearn.ensemble import RandomForestClassifier
            
            # Create simple preprocessing
            cat_pipe = Pipeline([
                ('imputer', SimpleImputer(strategy='constant', fill_value='')),
                ('encoder', OneHotEncoder(handle_unknown='ignore', sparse_output=False))
            ])
            
            num_pipe = Pipeline([
                ('imputer', SimpleImputer(strategy='constant', fill_value=0)),
                ('scaler', StandardScaler())
            ])
            
            preprocessor = ColumnTransformer(
                transformers=[
                    ('cat', cat_pipe, feature_info['cat_features']),
                    ('num', num_pipe, feature_info['num_features'] + 
                     feature_info['text_features'] + feature_info['semantic_features'])
                ],
                remainder='drop'
            )
            
            # Create a simple RandomForest model
            model = Pipeline([
                ('preprocessor', preprocessor),
                ('classifier', RandomForestClassifier(
                    n_estimators=50,
                    max_depth=10,
                    min_samples_split=10,
                    class_weight='balanced',
                    random_state=42,
                    n_jobs=-1,
                    verbose=1
                ))
            ])
            
            print("Training fast model...")
            model.fit(X_train, y_train)
        else:
            # Use the regular enhanced classifier
            model = build_enhanced_classifier(X_train, y_train, feature_info)
        
        training_time = time() - start_time
        print(f"Model training completed in {training_time:.1f} seconds")
        
        # Evaluate on test set
        print("\nEvaluating on test set:")
        report, cm, metrics = evaluate_model(model, X_test, y_test, os.path.dirname(args.output))
        
        # Save model
        os.makedirs(os.path.dirname(args.output), exist_ok=True)
        print(f"Saving model to {args.output}...")
        joblib.dump(model, args.output)
        print(f"Model saved successfully")
        
        # Save model summary
        summary_path = os.path.join(os.path.dirname(args.output), "model_summary.json")
        model_summary = {
            'accuracy': metrics['accuracy'],
            'f1_score': metrics['f1_score'],
            'total_samples': len(df),
            'training_samples': len(X_train),
            'test_samples': len(X_test),
            'class_count': len(np.unique(y)),
            'feature_count': len(X.columns),
            'training_time': training_time
        }
        
        import json
        with open(summary_path, 'w') as f:
            json.dump(model_summary, f, indent=2)
    
    # Evaluate on validation set if provided
    if args.validate:
        print("\nEvaluating on external validation set:")
        val_report, val_cm = evaluate_on_validation(model, args.validate, os.path.dirname(args.output))
    
    print("\nVulnerability classification complete.")
    return model
if __name__ == "__main__":
    main()

