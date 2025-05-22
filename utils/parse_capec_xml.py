import os
import json
import logging
import xml.etree.ElementTree as ET
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def parse_capec_xml(xml_path="data_collection/raw_data/capec_data/capec_v3.9.xml", 
                   output_json="data_collection/raw_data/capec_data/capec.json",
                   output_mapping="data_collection/raw_data/mappings/cwe_capec.csv"):
    """
    Parse CAPEC XML file to create:
    1. A JSON file with all CAPEC data
    2. A CSV file mapping CWEs to CAPECs
    
    This supports TWX's goal of unbiasing vulnerability data through proper classification
    by establishing clear relationships between weaknesses and attack patterns.
    """
    logger.info(f"Parsing CAPEC XML from {xml_path}")
    
    if not os.path.exists(xml_path):
        logger.error(f"CAPEC XML file not found: {xml_path}")
        return False
    
    try:
        # Parse the XML file
        tree = ET.parse(xml_path)
        root = tree.getroot()
        
        # Define namespace
        ns = {'capec': 'http://capec.mitre.org/capec-3'}
        
        # Extract attack patterns
        attack_patterns = []
        cwe_capec_mappings = []
        
        logger.info("Extracting attack patterns and CWE mappings...")
        
        for ap in root.findall(".//capec:Attack_Pattern", ns):
            pattern_id = ap.get('ID')
            if not pattern_id:
                continue
                
            capec_id = f"CAPEC-{pattern_id}"
            
            # Extract basic info
            name = ap.findtext(".//capec:Name", "", ns)
            summary = ap.findtext(".//capec:Summary", "", ns)
            likelihood = ap.findtext(".//capec:Likelihood_Of_Attack", "", ns)
            severity = ap.findtext(".//capec:Typical_Severity", "", ns)
            
            # Extract related weaknesses (CWEs)
            related_cwes = []
            for weakness in ap.findall(".//capec:Related_Weaknesses/capec:Related_Weakness", ns):
                cwe_id = weakness.get('CWE_ID')
                if cwe_id:
                    cwe_full_id = f"CWE-{cwe_id}"
                    related_cwes.append(cwe_full_id)
                    # Add to mappings list
                    cwe_capec_mappings.append((cwe_full_id, capec_id))
            
            # Build attack pattern object
            attack_pattern = {
                "id": pattern_id,
                "capec_id": capec_id,
                "name": name,
                "summary": summary,
                "likelihood": likelihood,
                "severity": severity,
                "related_weaknesses": related_cwes
            }
            
            attack_patterns.append(attack_pattern)
        
        # Create JSON structure
        capec_json = {
            "attack_patterns": attack_patterns,
            "version": "3.9",  # From filename
            "count": len(attack_patterns)
        }
        
        # Ensure output directories exist
        os.makedirs(os.path.dirname(output_json), exist_ok=True)
        os.makedirs(os.path.dirname(output_mapping), exist_ok=True)
        
        # Save JSON file
        with open(output_json, 'w', encoding='utf-8') as f:
            json.dump(capec_json, f, indent=2)
        
        logger.info(f"Saved {len(attack_patterns)} attack patterns to {output_json}")
        
        # Save CSV mapping file
        import csv
        with open(output_mapping, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["CWE_ID", "CAPEC_ID"])
            for cwe_id, capec_id in cwe_capec_mappings:
                writer.writerow([cwe_id, capec_id])
        
        logger.info(f"Saved {len(cwe_capec_mappings)} CWE-CAPEC mappings to {output_mapping}")
        
        # Create reverse mapping directories
        Path("data_collection/processed_data").mkdir(parents=True, exist_ok=True)
        
        # Create a JSON mapping dictionary (needed for some functions)
        mapping_dict = {}
        for cwe_id, capec_id in cwe_capec_mappings:
            if cwe_id not in mapping_dict:
                mapping_dict[cwe_id] = []
            if capec_id not in mapping_dict[cwe_id]:
                mapping_dict[cwe_id].append(capec_id)
        
        # Save JSON mapping
        with open("data_collection/processed_data/cwe_capec_mapping.json", 'w') as f:
            json.dump(mapping_dict, f, indent=2)
            
        logger.info(f"Saved mapping dictionary with {len(mapping_dict)} entries")
        
        return True
        
    except Exception as e:
        logger.error(f"Error parsing CAPEC XML: {e}")
        return False

if __name__ == "__main__":
    parse_capec_xml()