import os
import json
import sys
import glob
from tqdm import tqdm  # For progress bars

# Add parent directory to path to import from other modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from data_processing.parse_nvd import parse_nvd_record
from storage.vulnerability_db import VulnerabilityDatabase

RAW_NVD_BASE = "../data_collection/raw_data/nvd_data/"

def parse_nvd_directory(nvd_file_path):
    """
    Parse NVD records from a single JSON file.
    Returns a list of normalized vulnerability records ready for database insertion.
    """
    all_records = []
    
    with open(nvd_file_path, 'r', encoding='utf-8') as f:
        try:
            nvd_data = json.load(f)
            
            # NVD data structure has a 'CVE_Items' or 'vulnerabilities' array
            items = []
            if 'CVE_Items' in nvd_data:  # Older format
                items = nvd_data['CVE_Items']
            elif 'vulnerabilities' in nvd_data:  # Newer format
                items = nvd_data['vulnerabilities']
                
            for item in tqdm(items, desc=f"Parsing {os.path.basename(nvd_file_path)}"):
                try:
                    parsed_record = parse_nvd_record(item)
                    if parsed_record:
                        all_records.append(parsed_record)
                except Exception as e:
                    cve_id = item.get('cve', {}).get('CVE_data_meta', {}).get('ID', 'Unknown')
                    if not cve_id:
                        # Try the newer format
                        cve_id = item.get('cve', {}).get('id', 'Unknown')
                    print(f"Error parsing NVD record {cve_id}: {e}")
                    
        except Exception as e:
            print(f"Error processing NVD file {nvd_file_path}: {e}")
    
    return all_records

def main():
    """Parse all NVD files and store records directly in the database."""
    # Initialize database connection
    db = VulnerabilityDatabase()
    
    # Find all NVD JSON files
    nvd_files = glob.glob(os.path.join(RAW_NVD_BASE, "*.json"))
    
    if not nvd_files:
        print(f"No NVD JSON files found in {RAW_NVD_BASE}")
        return
    
    total_inserted = 0
    
    # Process each NVD file
    for nvd_file in nvd_files:
        print(f"Processing {os.path.basename(nvd_file)}...")
        nvd_records = parse_nvd_directory(nvd_file)
        
        # Store records in database
        inserted_count = db.batch_insert_vulnerabilities(nvd_records)
        total_inserted += inserted_count
        
        print(f"Inserted {inserted_count} of {len(nvd_records)} records from {os.path.basename(nvd_file)}")
    
    print(f"Total: Successfully inserted {total_inserted} NVD records into the database")
    
    # Close the database connection
    db.close()

if __name__ == "__main__":
    main()