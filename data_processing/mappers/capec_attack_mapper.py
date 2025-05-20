"""
Maps CAPEC attack patterns to MITRE ATT&CK techniques.
This allows for creating a full chain from vulnerabilities (CVE) to 
weaknesses (CWE) to attack patterns (CAPEC) to techniques (ATT&CK).
"""

import json
import os
import logging
from typing import Dict, List, Set

logger = logging.getLogger(__name__)

# Key CAPEC to ATT&CK mappings
# These are manually curated mappings for common attack patterns
CAPEC_ATTACK_MAPPING = {
    # Web Attacks
    'CAPEC-7': 'T1190',    # SQL Injection → Exploit Public-Facing Application
    'CAPEC-18': 'T1059',   # XSS → Command and Scripting Interpreter
    'CAPEC-63': 'T1059',   # Cross-Site Scripting → Command and Scripting Interpreter
    'CAPEC-88': 'T1059.4', # Command Injection → Command and Scripting Interpreter: Unix Shell
    'CAPEC-650': 'T1059.5', # Command Injection in Web Interface → PowerShell
    
    # Access Control
    'CAPEC-122': 'T1078',  # Privilege Abuse → Valid Accounts
    'CAPEC-233': 'T1110',  # Credential Brute Forcing → Brute Force
    'CAPEC-593': 'T1212',  # Authentication Bypass → Exploitation for Credential Access
    
    # Memory Safety
    'CAPEC-100': 'T1203',  # Overflow Buffers → Exploitation for Client Execution
    'CAPEC-14': 'T1068',   # Buffer Overflow → Exploitation for Privilege Escalation
    'CAPEC-123': 'T1068',  # Buffer Overflow → Exploitation for Privilege Escalation
    
    # Info Disclosure
    'CAPEC-116': 'T1082',  # Information Disclosure → System Information Discovery
    'CAPEC-150': 'T1557',  # Information Disclosure → Man in the Middle
    
    # File-related
    'CAPEC-126': 'T1083',  # Path Traversal → File and Directory Discovery
    'CAPEC-17': 'T1052',   # File Inclusion → Exfiltration Over Physical Medium
}

def load_capec_data(capec_json_path: str = "data_collection/raw_data/capec_data/capec.json"):
    """Load CAPEC data from JSON file."""
    try:
        if not os.path.exists(capec_json_path):
            logger.warning(f"CAPEC JSON file not found: {capec_json_path}")
            return None
            
        with open(capec_json_path, 'r') as f:
            capec_data = json.load(f)
        
        return capec_data
    except Exception as e:
        logger.error(f"Error loading CAPEC data: {e}")
        return None

def generate_capec_attack_mapping(capec_data=None, output_path="data_collection/processed_data/capec_attack_mapping.json"):
    """Generate a comprehensive mapping from CAPEC to ATT&CK techniques."""
    if capec_data is None:
        capec_data = load_capec_data()
        if not capec_data:
            return CAPEC_ATTACK_MAPPING
    
    # Start with the basic mapping
    mapping = dict(CAPEC_ATTACK_MAPPING)
    
    # Try to extract additional mappings from CAPEC data if available
    if capec_data and isinstance(capec_data, dict) and 'attack_patterns' in capec_data:
        for pattern in capec_data['attack_patterns']:
            capec_id = pattern.get('id')
            if not capec_id:
                continue
                
            # Look for ATT&CK references in the description or references
            description = pattern.get('description', '')
            references = pattern.get('references', [])
            
            # Extract ATT&CK technique IDs from the description
            technique_ids = set()
            technique_matches = re.findall(r'T\d{4}(?:\.\d{3})?', description)
            technique_ids.update(technique_matches)
            
            # Check references for ATT&CK links
            for ref in references:
                ref_url = ref.get('url', '')
                if 'attack.mitre.org' in ref_url:
                    # Extract technique ID from URL
                    technique_match = re.search(r'techniques/(T\d{4}(?:\.\d{3})?)', ref_url)
                    if technique_match:
                        technique_ids.add(technique_match.group(1))
            
            # Add to mapping if we found technique IDs
            if technique_ids and capec_id not in mapping:
                # Just use the first technique ID for now (could be expanded to support multiple)
                mapping[capec_id] = next(iter(technique_ids))
    
    # Save the mapping
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(mapping, f, indent=2)
    
    logger.info(f"Saved CAPEC to ATT&CK mapping with {len(mapping)} entries to {output_path}")
    return mapping

def get_attack_techniques_for_capec(capec_ids, mapping=None):
    """
    Get ATT&CK techniques associated with given CAPEC IDs.
    
    Args:
        capec_ids: List of CAPEC IDs (e.g., ['CAPEC-7', 'CAPEC-63'])
        mapping: Optional pre-loaded mapping dictionary
        
    Returns:
        List of ATT&CK technique IDs
    """
    if mapping is None:
        mapping = CAPEC_ATTACK_MAPPING
        
    attack_techniques = []
    for capec_id in capec_ids:
        if capec_id in mapping:
            attack_technique = mapping[capec_id]
            if attack_technique not in attack_techniques:
                attack_techniques.append(attack_technique)
    
    return attack_techniques

def get_attack_techniques_for_cwe(cwe_id, cwe_capec_mapping=None, capec_attack_mapping=None):
    """
    Get ATT&CK techniques associated with a given CWE.
    
    Args:
        cwe_id: CWE ID (e.g., 'CWE-89')
        cwe_capec_mapping: Optional pre-loaded CWE to CAPEC mapping
        capec_attack_mapping: Optional pre-loaded CAPEC to ATT&CK mapping
        
    Returns:
        List of ATT&CK technique IDs
    """
    if cwe_capec_mapping is None:
        # Import here to avoid circular imports
        from data_processing.mappers.cwe_capec_mapper import load_cwe_capec_mapping
        cwe_capec_mapping = load_cwe_capec_mapping()
        
    if capec_attack_mapping is None:
        capec_attack_mapping = CAPEC_ATTACK_MAPPING
    
    # Get CAPEC IDs for the CWE
    capec_ids = cwe_capec_mapping.get(cwe_id, [])
    if not isinstance(capec_ids, list):
        capec_ids = [capec_ids]
    
    # Map CAPEC IDs to ATT&CK techniques
    return get_attack_techniques_for_capec(capec_ids, capec_attack_mapping)