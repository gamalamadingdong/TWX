# analysis/explore_data.py
import json
import pandas as pd
from collections import Counter
import matplotlib.pyplot as plt

def load_processed_data(path="data_collection/processed_data/unified_vulns.json"):
    """Load processed vulnerability data."""
    with open(path, 'r') as f:
        return json.load(f)

def basic_stats(vulns):
    """Generate basic statistics about the dataset."""
    print(f"Total vulnerabilities: {len(vulns)}")
    
    # Count vulnerabilities by CWE
    cwe_counter = Counter()
    for vuln in vulns:
        for cwe in vuln.get("cwe", []):
            cwe_counter[cwe] += 1
    
    print("\nTop 10 CWEs:")
    for cwe, count in cwe_counter.most_common(10):
        print(f"  {cwe}: {count}")
    
    # Count vulnerabilities by vendor
    vendor_counter = Counter()
    for vuln in vulns:
        for product in vuln.get("products", []):
            vendor_counter[product.get("vendor", "")] += 1
    
    print("\nTop 10 Vendors:")
    for vendor, count in vendor_counter.most_common(10):
        if vendor:  # Skip empty vendor names
            print(f"  {vendor}: {count}")
    
    # Count ATT&CK techniques
    technique_counter = Counter()
    for vuln in vulns:
        for tech in vuln.get("attack_technique", []):
            technique_counter[tech] += 1
    
    print("\nTop 10 ATT&CK Techniques:")
    for tech, count in technique_counter.most_common(10):
        print(f"  {tech}: {count}")

def create_cvss_histogram(vulns):
    """Create histogram of CVSS scores."""
    scores = [vuln.get("cvss", {}).get("base_score", 0) for vuln in vulns]
    scores = [s for s in scores if s > 0]  # Filter out zeros
    
    plt.figure(figsize=(10, 6))
    plt.hist(scores, bins=20)
    plt.xlabel('CVSS Score')
    plt.ylabel('Count')
    plt.title('Distribution of CVSS Scores')
    plt.savefig('analysis/cvss_histogram.png')
    plt.close()
    
    print(f"\nCVSS Statistics:")
    print(f"  Mean: {sum(scores)/len(scores) if scores else 0:.2f}")
    print(f"  Min: {min(scores) if scores else 0}")
    print(f"  Max: {max(scores) if scores else 0}")

def prepare_for_classification(vulns, output="analysis/classification_data.csv"):
    """Create a CSV file with features for classification."""
    # Extract features
    data = []
    for vuln in vulns:
        cat_features = vuln.get("categorical_features", {})
        num_features = vuln.get("numerical_features", {})
        
        row = {
            "id": vuln.get("id", ""),
            "cwe": cat_features.get("cwe", ""),
            "vendor": cat_features.get("vendor", ""),
            "product": cat_features.get("product", ""),
            "attack_vector": cat_features.get("attack_vector", ""),
            "attack_complexity": cat_features.get("attack_complexity", ""),
            "privileges_required": cat_features.get("privileges_required", ""),
            "user_interaction": cat_features.get("user_interaction", ""),
            "known_exploited": cat_features.get("known_exploited", 0),
            "base_score": num_features.get("base_score", 0),
            "product_count": num_features.get("product_count", 0),
            "reference_count": num_features.get("reference_count", 0),
            "year": num_features.get("year", 0),
            "has_capec": 1 if vuln.get("capec") else 0,
            "has_attack": 1 if vuln.get("attack_technique") else 0
        }
        data.append(row)
    
    # Convert to DataFrame and save
    df = pd.DataFrame(data)
    df.to_csv(output, index=False)
    print(f"\nClassification dataset written to {output} ({len(df)} rows)")
    
    return df

if __name__ == "__main__":
    # Load data
    vulns = load_processed_data()
    
    # Run analysis
    basic_stats(vulns)
    create_cvss_histogram(vulns)
    
    # Prepare for classification
    df = prepare_for_classification(vulns)
    
    # Report class distribution for potential classification tasks
    print("\nPotential Classification Tasks:")
    
    # CWE classification
    cwe_counts = df["cwe"].value_counts()
    print(f"  CWE Classes: {len(cwe_counts)} unique values")
    print(f"  Top 5: {cwe_counts.head(5).to_dict()}")
    
    # Exploitability classification
    expl_counts = df["known_exploited"].value_counts()
    print(f"  Known Exploited: {expl_counts.to_dict()}")
    
    # CVSS severity bins
    df["severity"] = pd.cut(df["base_score"], 
                           bins=[0, 3.9, 6.9, 8.9, 10.0],
                           labels=["Low", "Medium", "High", "Critical"])
    sev_counts = df["severity"].value_counts()
    print(f"  Severity Classes: {sev_counts.to_dict()}")