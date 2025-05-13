import os
import json
import sys
from pathlib import Path

# Add parent directory to path to import from other modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from data_processing.parse_cve import parse_cve_record
from storage.vulnerability_db import VulnerabilityDatabase

RAW_CVE_BASE = "../data_collection/raw_data/cve_data/cves/"

def is_relevant_year(dirname):
    """Only process directories named as years 2021 or later"""
    try:
        year = int(dirname)
        return year >= 2021  # Changed to include more data for better analysis
    except ValueError:
        return False

def parse_cve_directory(directory_path=RAW_CVE_BASE):
    """
    Parse all CVE records from the specified directory structure.
    Returns a list of normalized vulnerability records ready for database insertion.
    """
    all_records = []
    num_files = 0
    
    for year_dir in os.listdir(directory_path):
        if not is_relevant_year(year_dir):
            continue
            
        year_path = os.path.join(directory_path, year_dir)
        if not os.path.isdir(year_path):
            continue
            
        # Now enumerate subdirectories (e.g., 3xxx, 4xxx, etc.)
        for sub_dir in os.listdir(year_path):
            sub_path = os.path.join(year_path, sub_dir)
            if not os.path.isdir(sub_path):
                continue
                
            for fname in os.listdir(sub_path):
                if not fname.endswith(".json"):
                    continue

                fpath = os.path.join(sub_path, fname)
                num_files += 1
                
                # Progress reporting for every 100 files
                if num_files % 100 == 0:
                    print(f"Processing file {num_files}...")
                    
                with open(fpath, "r", encoding="utf-8") as f:
                    try:
                        raw = json.load(f)
                        parsed_record = parse_cve_record(raw)
                        all_records.append(parsed_record)
                    except Exception as e:
                        print(f"Error parsing {fpath}: {e}")
    
    print(f"Processed {num_files} CVE files, found {len(all_records)} valid records")
    return all_records

def main():
    """Parse CVE records and store them directly in the database."""
    # Initialize database connection
    db = VulnerabilityDatabase()
    
    # Parse CVE records
    print("Parsing CVE records...")
    cve_records = parse_cve_directory(RAW_CVE_BASE)
    
    # Store records in the database
    print("Storing records in database...")
    inserted_count = db.batch_insert_vulnerabilities(cve_records)
    
    print(f"Successfully inserted {inserted_count} of {len(cve_records)} CVE records into the database")
    
    # Close the database connection
    db.close()

if __name__ == "__main__":
    main()