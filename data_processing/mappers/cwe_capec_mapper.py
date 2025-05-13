# data_processing/mappers/cwe_capec_mapper.py
import json
import csv
import os

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