from storage.vulnerability_db import VulnerabilityDatabase
from data_processing.parse_cwe import parse_cwe_xml
import os
import logging

logger = logging.getLogger(__name__)

def ingest_cwe_data():
    """Ingest CWE data from XML file into database."""
    db = VulnerabilityDatabase()
    
    # Find the correct path to the XML file
    cwe_file = "data_collection/raw_data/cwe_data/cwec_latest.xml/cwec_v4.17.xml"
    if not os.path.exists(cwe_file):
        cwe_file = "data_collection/raw_data/cwe_data/cwec_v4.17.xml"
        if not os.path.exists(cwe_file):
            cwe_file = "data_collection/raw_data/cwe_data/cwec_v4.13.xml"
            if not os.path.exists(cwe_file):
                logger.error(f"ERROR: CWE XML file not found at any expected path")
                return
    
    logger.info(f"Parsing CWE data from {cwe_file}")
    cwe_entries = parse_cwe_xml(cwe_file)

    if not cwe_entries:
        logger.error("No CWE entries found in the XML file. Check the XML format or parser.")
        return

    logger.info(f"Ingesting {len(cwe_entries)} CWE entries into the database...")
    success_count = 0
    for entry in cwe_entries:
        if db.insert_cwe(entry):
            success_count += 1
    
    logger.info(f"CWE data ingestion complete. Successfully inserted {success_count} of {len(cwe_entries)} entries.")
    
    # Close the database connection when all operations are complete
    db.close()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    ingest_cwe_data()