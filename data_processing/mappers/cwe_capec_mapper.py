# data_processing/mappers/cwe_capec_mapper.py
import json
import csv
import os
import xml.etree.ElementTree as ET
import logging

def load_cwe_capec_mapping(mapping_file="data_collection/raw_data/mappings/cwe_capec.csv"):
    """Load or generate CWE to CAPEC mapping."""
    mapping = {}
    
    # If mapping file exists, load it
    if os.path.exists(mapping_file):
        with open(mapping_file, 'r') as f:
            reader = csv.reader(f)
            next(reader)  # Skip header
            for row in reader:
                cwe_id, capec_id = row[0], row[1]
                mapping.setdefault(cwe_id, []).append(capec_id)
        return mapping
    
    # Otherwise, generate from CAPEC data
    # Note: You would need to download CAPEC data first
    capec_file = "data_collection/raw_data/capec_data/capec.json"
    if not os.path.exists(capec_file):
        print(f"Error: {capec_file} not found")
        return mapping
    
    with open(capec_file, 'r') as f:
        capec_data = json.load(f)
    
    # Extract CWE-CAPEC relationships
    for attack_pattern in capec_data.get("attack_patterns", []):
        capec_id = attack_pattern.get("id")
        related_weaknesses = attack_pattern.get("related_weaknesses", [])
        
        for weakness in related_weaknesses:
            cwe_id = f"CWE-{weakness.get('cwe_id')}"
            mapping.setdefault(cwe_id, []).append(f"CAPEC-{capec_id}")
    
    # Save mapping for future use
    os.makedirs(os.path.dirname(mapping_file), exist_ok=True)
    with open(mapping_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["CWE_ID", "CAPEC_ID"])
        for cwe_id, capec_ids in mapping.items():
            for capec_id in capec_ids:
                writer.writerow([cwe_id, capec_id])
    
    return mapping

def map_cwe_to_capec(vulns, mapping=None):
    """Enrich vulnerabilities with CAPEC IDs based on CWE."""
    if mapping is None:
        mapping = load_cwe_capec_mapping()
    
    for vuln in vulns:
        capecs = []
        for cwe in vuln.get("cwe", []):
            if cwe in mapping:
                capecs.extend(mapping[cwe])
        vuln["capec"] = list(set(capecs))  # Deduplicate
    
    return vulns

def generate_cwe_capec_mapping(cwe_xml_path=None, capec_xml_path=None, output_path=None):
    """
    Generate a mapping between CWE and CAPEC IDs by parsing the XML files.
    
    This function supports TWX's goal of unbiasing vulnerability data through proper
    classification by creating links between weaknesses and attack patterns.
    
    Args:
        cwe_xml_path: Path to the CWE XML file
        capec_xml_path: Path to the CAPEC XML file
        output_path: Path to save the mapping JSON file
        
    Returns:
        Dictionary mapping CWE IDs to CAPEC IDs
    """
    import os
    import json
    import xml.etree.ElementTree as ET
    import logging
    
    logger = logging.getLogger(__name__)
    
    # Default paths based on TWX project structure
    if cwe_xml_path is None:
        cwe_xml_path = "data_collection/raw_data/cwe_data/cwec_v4.13.xml"
    
    if capec_xml_path is None:
        capec_xml_path = "data_collection/raw_data/capec_data/capec_v3.9.xml"
        
    if output_path is None:
        output_path = "data_collection/processed_data/cwe_capec_mapping.json"
    
    logger.info(f"Generating CWE-CAPEC mapping from {cwe_xml_path} and {capec_xml_path}")
    
    mapping = {}
    
    # Check if files exist
    if not os.path.exists(cwe_xml_path):
        logger.warning(f"CWE XML file not found: {cwe_xml_path}")
        return mapping
        
    try:
        # Step 1: Extract CAPEC references from CWE XML
        tree = ET.parse(cwe_xml_path)
        root = tree.getroot()
        namespace = {'cwe': 'http://cwe.mitre.org/cwe-7'}
        
        # Process each weakness
        for weakness in root.findall(".//cwe:Weakness", namespace):
            cwe_id = f"CWE-{weakness.get('ID', '')}"
            attack_patterns = []
            
            # Get directly referenced CAPECs
            for related_attack_pattern in weakness.findall(".//cwe:Related_Attack_Patterns/cwe:Related_Attack_Pattern", namespace):
                capec_id = related_attack_pattern.get('CAPEC_ID')
                if capec_id:
                    attack_patterns.append(f"CAPEC-{capec_id}")
            
            if attack_patterns:
                mapping[cwe_id] = attack_patterns
        
        # Step 2: If available, also check CAPEC XML for CWE references
        if os.path.exists(capec_xml_path):
            try:
                capec_tree = ET.parse(capec_xml_path)
                capec_root = capec_tree.getroot()
                capec_namespace = {'capec': 'http://capec.mitre.org/capec-3'}
                
                for attack_pattern in capec_root.findall(".//capec:Attack_Pattern", capec_namespace):
                    capec_id = f"CAPEC-{attack_pattern.get('ID', '')}"
                    
                    # Look for CWE references in this CAPEC
                    for related_weakness in attack_pattern.findall(".//capec:Related_Weaknesses/capec:Related_Weakness", capec_namespace):
                        cwe_id = f"CWE-{related_weakness.get('CWE_ID', '')}"
                        
                        # Add to our mapping (CWE->CAPEC)
                        if cwe_id not in mapping:
                            mapping[cwe_id] = [capec_id]
                        elif capec_id not in mapping[cwe_id]:
                            mapping[cwe_id].append(capec_id)
            except Exception as e:
                logger.warning(f"Error processing CAPEC XML: {e}")
        
        # Step 3: Save the mapping to JSON file
        if mapping:
            # Make directory if it doesn't exist
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            
            with open(output_path, 'w') as f:
                json.dump(mapping, f, indent=2)
                
            logger.info(f"Generated CWE-CAPEC mapping with {len(mapping)} entries to {output_path}")
            
            # Also create a CSV version for easier reference
            csv_path = os.path.join(os.path.dirname(output_path), "cwe_capec.csv")
            
            try:
                with open(csv_path, 'w') as f:
                    f.write("CWE_ID,CAPEC_ID\n")
                    for cwe, capecs in mapping.items():
                        for capec in capecs:
                            f.write(f"{cwe},{capec}\n")
                logger.info(f"Generated CSV mapping to {csv_path}")
            except:
                logger.warning("Could not generate CSV version of mapping")
        else:
            logger.warning("No CWE-CAPEC mappings found")
        
        return mapping
    
    except Exception as e:
        logger.error(f"Failed to generate CWE-CAPEC mapping: {e}")
        return mapping