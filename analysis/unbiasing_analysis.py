import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import os
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from storage.vulnerability_db import VulnerabilityDatabase

def analyze_unbiasing_effect():
    """
    Analyze and visualize how proper classification removes bias in vulnerability data.
    This demonstrates the core value proposition of TWX.
    """
    # Initialize database connection
    db = VulnerabilityDatabase()
    
    # Get raw vulnerability data
    df = db.export_to_csv("analysis/classification_data.csv")
    
    # Set up the plot
    plt.figure(figsize=(12, 10))
    
    # 1. Raw CWE Distribution (potentially biased)
    plt.subplot(2, 1, 1)
    cwe_counts = df['cwe'].value_counts().head(10)
    sns.barplot(y=cwe_counts.index, x=cwe_counts.values, palette="Blues_d")
    plt.title("Raw CWE Distribution (Potentially Biased)")
    plt.xlabel("Count")
    plt.ylabel("CWE")
    plt.tight_layout()
    
    # 2. Classified Vulnerability Types (unbiased)
    df['vuln_type'] = df['cwe'].apply(lambda x: map_cwe_to_vuln_type(str(x)))
    
    plt.subplot(2, 1, 2)
    type_counts = df['vuln_type'].value_counts().head(10)
    sns.barplot(y=type_counts.index, x=type_counts.values, palette="Reds_d")
    plt.title("Classified Vulnerability Types (Unbiased View)")
    plt.xlabel("Count")
    plt.ylabel("Vulnerability Type")
    plt.tight_layout()
    
    # Save the figure
    os.makedirs("analysis/figures", exist_ok=True)
    plt.savefig("analysis/figures/unbiasing_effect.png")
    plt.close()
    
    # 3. Services affected by each vulnerability type
    plt.figure(figsize=(14, 12))
    
    # Top vulnerability types
    top_types = df['vuln_type'].value_counts().head(5).index.tolist()
    
    # For each top type, get top 5 services
    for i, vuln_type in enumerate(top_types):
        plt.subplot(len(top_types), 1, i+1)
        
        # Filter to this vulnerability type
        type_df = df[df['vuln_type'] == vuln_type]
        
        # Count services
        service_counts = type_df['product'].value_counts().head(10)
        
        # Plot
        sns.barplot(y=service_counts.index, x=service_counts.values, palette="viridis")
        plt.title(f"Top Services Affected by {vuln_type}")
        plt.xlabel("Count")
        plt.ylabel("Service")
        plt.tight_layout()
    
    # Save the figure
    plt.savefig("analysis/figures/services_by_vuln_type.png")
    plt.close()
    
    # Print statistical summary
    print("\nUnbiasing Analysis:")
    print(f"Raw number of CWEs: {df['cwe'].nunique()}")
    print(f"Consolidated vulnerability types: {df['vuln_type'].nunique()}")
    print("\nTop 5 vulnerability types:")
    for vuln_type, count in df['vuln_type'].value_counts().head(5).items():
        print(f"  {vuln_type}: {count} vulnerabilities")
    
    # Close database connection
    db.close()

def map_cwe_to_vuln_type(cwe):
    """Map CWE IDs to vulnerability types/categories."""
    # Import this from models/vuln_classifier.py to keep mapping consistent
    from models.vuln_classifier import map_cwe_to_vuln_type as classifier_map
    return classifier_map(cwe)

if __name__ == "__main__":
    analyze_unbiasing_effect()