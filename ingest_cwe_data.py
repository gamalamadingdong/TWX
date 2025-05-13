from storage.vulnerability_db import VulnerabilityDatabase
from data_processing.parse_cwe import parse_cwe_xml
import os

def ingest_cwe_data():
    db = VulnerabilityDatabase()
    
    # Find the correct path to the XML file
    cwe_file = "data_collection/raw_data/cwe_data/cwec_latest.xml/cwec_v4.17.xml"
    if not os.path.exists(cwe_file):
        cwe_file = "data_collection/raw_data/cwe_data/cwec_v4.17.xml"
        if not os.path.exists(cwe_file):
            print(f"ERROR: CWE XML file not found at either path")
            return
    
    cwe_entries = parse_cwe_xml(cwe_file)

    print(f"Ingesting {len(cwe_entries)} CWE entries into the database...")
    success_count = 0
    for entry in cwe_entries:
        if db.insert_cwe(entry):
            success_count += 1
    
    print(f"CWE data ingestion complete. Successfully inserted {success_count} of {len(cwe_entries)} entries.")
    
    # Close the database connection when all operations are complete
    db.close()

if __name__ == "__main__":
    ingest_cwe_data()