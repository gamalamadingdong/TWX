"""
Feature extraction utilities for the TWX vulnerability classification model.
"""

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
import re

def extract_text_features(df, text_column='description', max_features=100):
    """
    Extract TF-IDF features from text descriptions.
    
    Args:
        df: DataFrame containing the text column
        text_column: Column name containing text to analyze
        max_features: Maximum number of features to extract
        
    Returns:
        DataFrame with text features
    """
    print(f"Extracting text features from '{text_column}'")
    
    # Ensure text column exists
    if text_column not in df.columns:
        print(f"Warning: '{text_column}' column not found, returning empty DataFrame")
        return pd.DataFrame()
    
    # Fill missing values and convert to string
    text_data = df[text_column].fillna('').astype(str)
    
    # Create TF-IDF features
    tfidf = TfidfVectorizer(
        max_features=max_features,
        stop_words='english',
        ngram_range=(1, 2),  # Unigrams and bigrams
        min_df=5,  # Ignore terms that appear in less than 5 documents
        norm='l2',
        use_idf=True
    )
    
    # Transform text to feature vectors
    text_features = tfidf.fit_transform(text_data)
    
    # Convert to DataFrame with feature names
    feature_names = [f'txt_{i}' for i in range(text_features.shape[1])]
    text_features_df = pd.DataFrame(
        text_features.toarray(),
        index=df.index,
        columns=feature_names
    )
    
    print(f"Generated {text_features.shape[1]} text features")
    
    # Store the top terms for interpretability
    top_terms = {}
    for i, feature_name in enumerate(tfidf.get_feature_names_out()):
        top_terms[f'txt_{i}'] = feature_name
    
    # Print some example mappings
    print("Example text features:")
    for i, (feature, term) in enumerate(top_terms.items()):
        if i < 10:  # Print just the first 10
            print(f"  {feature}: {term}")
    
    return text_features_df, top_terms

def extract_semantic_features(df):
    """
    Extract semantic features like reference counts, patch status, etc.
    
    Args:
        df: DataFrame containing vulnerability data
        
    Returns:
        DataFrame with semantic features
    """
    features = pd.DataFrame(index=df.index)
    
    # Reference patterns
    if 'references' in df.columns:
        refs = df['references'].fillna('')
        features['has_patch_ref'] = refs.str.contains('patch|update|upgrade|fix', case=False).astype(int)
        features['has_exploit_ref'] = refs.str.contains('exploit|poc|proof|attack', case=False).astype(int)
        features['has_advisory_ref'] = refs.str.contains('advisory|security|bulletin', case=False).astype(int)
    
    # Description semantic features
    if 'description' in df.columns:
        desc = df['description'].fillna('')
        features['desc_mentions_overflow'] = desc.str.contains('overflow|buffer|stack|heap', case=False).astype(int)
        features['desc_mentions_injection'] = desc.str.contains('injection|inject|sql|xss|script', case=False).astype(int)
        features['desc_mentions_auth'] = desc.str.contains('authentica|login|password|credential', case=False).astype(int)
        features['desc_mentions_dos'] = desc.str.contains('denial of service|crash|dos', case=False).astype(int)
    
    return features

def combine_features(df, include_text=True, include_semantic=True, text_max_features=100):
    """
    Combine all feature types into a single feature matrix.
    
    Args:
        df: DataFrame containing vulnerability data
        include_text: Whether to include text features
        include_semantic: Whether to include semantic features
        text_max_features: Maximum number of text features
        
    Returns:
        DataFrame with combined features
    """
    features_list = []
    
    # Original features (non-text categorical and numerical)
    cat_features = ["vendor", "product", "av", "ac", "pr", "ui",
                    "known_exploited", "has_cisa_advisory", "has_vendor_advisory"]
    num_features = ["base_score", "product_count", "reference_count", 
                    "days_to_patch", "exploit_maturity"]
    
    # Select original features that exist in the DataFrame
    existing_features = []
    for feat in cat_features + num_features:
        if feat in df.columns:
            existing_features.append(feat)
    
    base_features = df[existing_features].copy()
    features_list.append(base_features)
    
    # Add text features if requested
    if include_text and 'description' in df.columns:
        text_features, _ = extract_text_features(df, text_column='description', max_features=text_max_features)
        features_list.append(text_features)
    
    # Add semantic features if requested
    if include_semantic:
        semantic_features = extract_semantic_features(df)
        features_list.append(semantic_features)
    
    # Combine all features
    combined_features = pd.concat(features_list, axis=1)
    
    print(f"Combined feature set contains {combined_features.shape[1]} features")
    return combined_features