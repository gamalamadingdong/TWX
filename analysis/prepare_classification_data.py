import json
import pandas as pd
import os
from datetime import datetime
import sys

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from storage.vulnerability_db import VulnerabilityDatabase

def extract_features_from_db(db_path="data_processing/data/twx_vulnerabilities.db", output_path="analysis/classification_data.csv"):
    """Extract classification features directly from the SQLite database."""
    
    # Initialize database connection
    db = VulnerabilityDatabase(db_path)
    
    # Export data to CSV with all necessary features
    df = db.export_to_csv(output_path)
    
    # Close database connection
    db.close()
    
    return df

def process_all_data():
    """Process all data sources and store in SQLite database."""
    # Initialize database
    db = VulnerabilityDatabase()
    
    # Process CVE data
    cve_dir = "raw_data/cve_data/cves"
    if os.path.exists(cve_dir):
        print(f"Processing CVE data from {cve_dir}...")
        cve_records = parse_cve_directory(cve_dir)
        inserted = db.batch_insert_vulnerabilities(cve_records)
        print(f"Inserted {inserted} CVE records into database")
    else:
        print(f"Warning: CVE directory not found at {cve_dir}")
    
    # Process NVD data
    nvd_dir = "raw_data/nvd_data"
    if os.path.exists(nvd_dir):
        print(f"Processing NVD data from {nvd_dir}...")
        nvd_files = [f for f in os.listdir(nvd_dir) if f.endswith('.json')]
        
        for nvd_file in nvd_files:
            file_path = os.path.join(nvd_dir, nvd_file)
            print(f"Processing {file_path}...")
            nvd_records = parse_nvd_directory(file_path)
            inserted = db.batch_insert_vulnerabilities(nvd_records)
            print(f"Inserted {inserted} NVD records from {nvd_file} into database")
    else:
        print(f"Warning: NVD directory not found at {nvd_dir}")
    
    print("All data processed and stored in SQLite database")
    return db

if __name__ == "__main__":
    # Process and store data in SQLite
    db = process_all_data()
    
    # Extract features directly from database
    df = extract_features_from_db()
    
    # Print summary statistics
    print(f"\nDataset statistics:")
    print(f"  Total vulnerabilities: {len(df)}")
    print(f"  Known exploited: {df['known_exploited'].sum()} ({df['known_exploited'].sum()/len(df)*100:.1f}%)")
    print(f"  With CISA advisory: {df['has_cisa_advisory'].sum()} ({df['has_cisa_advisory'].sum()/len(df)*100:.1f}%)")
    print(f"  With vendor advisory: {df['has_vendor_advisory'].sum()} ({df['has_vendor_advisory'].sum()/len(df)*100:.1f}%)")
    
    # This field may need to be created by the export_to_csv method
    if 'has_attack_mapping' in df.columns:
        print(f"  With ATT&CK mapping: {df['has_attack_mapping'].sum()} ({df['has_attack_mapping'].sum()/len(df)*100:.1f}%)")