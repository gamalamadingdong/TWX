import json
import os
import sys
import time

# Add parent directory to path to import from other modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mappers.cwe_capec_mapper import map_cwe_to_capec
from mappers.capec_attack_mapper import map_capec_to_attack
from normalizers.feature_extractor import (
    extract_cvss_components,
    extract_categorical_features,
    extract_numerical_features
)
from data_processing.parse_cve_dir import parse_cve_directory
from data_processing.parse_nvd_dir import parse_nvd_directory
from storage.vulnerability_db import VulnerabilityDatabase

def merge_cve_nvd(cve_path, nvd_path):
    """Merge CVE and NVD data by ID."""
    with open(cve_path, 'r') as f:
        cve_data = json.load(f)
    
    with open(nvd_path, 'r') as f:
        nvd_data = json.load(f)
    
    # Create a dictionary of NVD entries by CVE ID
    nvd_dict = {item["id"]: item for item in nvd_data}
    
    merged = []
    for cve in cve_data:
        cve_id = cve["id"]
        if cve_id in nvd_dict:
            # Merge the two entries
            nvd_entry = nvd_dict[cve_id]
            
            # Prefer NVD CVSS if available
            if nvd_entry.get("cvss") and not cve.get("cvss"):
                cve["cvss"] = nvd_entry["cvss"]
            
            # Merge products
            cve_products = {(p["vendor"], p["product"], p["version"]) for p in cve.get("products", [])}
            for product in nvd_entry.get("products", []):
                product_tuple = (product["vendor"], product["product"], product["version"])
                if product_tuple not in cve_products:
                    cve.setdefault("products", []).append(product)
                    cve_products.add(product_tuple)
            
            # Merge references
            cve_refs = set(cve.get("references", []))
            for ref in nvd_entry.get("references", []):
                if ref not in cve_refs:
                    cve.setdefault("references", []).append(ref)
                    cve_refs.add(ref)
            
            merged.append(cve)
        else:
            # Just add the CVE entry
            merged.append(cve)
    
    # Add any NVD entries not in CVE
    cve_ids = {item["id"] for item in cve_data}
    for nvd_entry in nvd_data:
        if nvd_entry["id"] not in cve_ids:
            merged.append(nvd_entry)
    
    return merged

def process_all_data():
    """Process all vulnerability data and store in SQLite database."""
    start_time = time.time()
    
    # Initialize database
    print("Initializing database...")
    db = VulnerabilityDatabase()
    
    # Process CVE data
    cve_dir = os.path.abspath("./data_collection/raw_data/cve_data/cves")
    if os.path.exists(cve_dir):
        print(f"Processing CVE data from {cve_dir}...")
        cve_records = parse_cve_directory(cve_dir)
        inserted = db.batch_insert_vulnerabilities(cve_records)
        print(f"Inserted {inserted} of {len(cve_records)} CVE records into database")
    else:
        print(f"Warning: CVE directory not found at {cve_dir}")
    
    # Process NVD data
    nvd_dir = os.path.abspath("./data_collection/raw_data/nvd_data")
    if os.path.exists(nvd_dir):
        print(f"Processing NVD data from {nvd_dir}...")
        nvd_files = [f for f in os.listdir(nvd_dir) if f.endswith('.json')]
        
        total_inserted = 0
        for nvd_file in nvd_files:
            file_path = os.path.join(nvd_dir, nvd_file)
            print(f"Processing {nvd_file}...")
            nvd_records = parse_nvd_directory(file_path)
            inserted = db.batch_insert_vulnerabilities(nvd_records)
            total_inserted += inserted
            print(f"Inserted {inserted} of {len(nvd_records)} records from {nvd_file}")
        
        print(f"Total: Inserted {total_inserted} NVD records into database")
    else:
        print(f"Warning: NVD directory not found at {nvd_dir}")
    
    # Extract classification data
    print("Extracting classification data for analysis...")
    df = db.export_to_csv("analysis/classification_data.csv")
    print(f"Created classification dataset with {len(df)} records")
    
    # Close database connection
    db.close()
    
    elapsed_time = time.time() - start_time
    print(f"All processing completed in {elapsed_time:.2f} seconds")
    
    return db

if __name__ == "__main__":
    process_all_data()