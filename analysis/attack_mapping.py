import os
import sys
import pandas as pd
import re
import json

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from storage.vulnerability_db import VulnerabilityDatabase

# More comprehensive CWE to ATT&CK mappings
CWE_ATTACK_MAPPINGS = {
    # Injection vulnerabilities
    'CWE-79': ['T1059', 'T1189'],  # XSS -> Command and Scripting Interpreter, Drive-by Compromise
    'CWE-89': ['T1190', 'T1212'],  # SQL Injection -> Exploit Public-Facing Application, Exploitation for Credential Access
    'CWE-78': ['T1059'],  # OS Command Injection -> Command and Scripting Interpreter
    'CWE-77': ['T1059'],  # Command Injection -> Command and Scripting Interpreter

    # Authentication/Access Control issues
    'CWE-287': ['T1110', 'T1556'],  # Improper Authentication -> Brute Force, Modify Authentication Process
    'CWE-284': ['T1548', 'T1134'],  # Access Control Issues -> Abuse Elevation Control Mechanism, Access Token Manipulation
    'CWE-306': ['T1078'],  # Missing Authentication -> Valid Accounts
    'CWE-522': ['T1110', 'T1212'],  # Weak Credentials -> Brute Force, Exploitation for Credential Access

    # Information disclosure
    'CWE-200': ['T1555', 'T1552'],  # Information Exposure -> Credentials from Password Stores, Unsecured Credentials
    'CWE-209': ['T1212'],  # Error Information Leak -> Exploitation for Credential Access
    
    # File-related vulnerabilities
    'CWE-22': ['T1083', 'T1082'],  # Path Traversal -> File and Directory Discovery, System Information Discovery
    'CWE-434': ['T1105', 'T1204'],  # Unrestricted Upload -> Ingress Tool Transfer, User Execution
    'CWE-73': ['T1036', 'T1574'],  # External Control of File Name -> Masquerading, Hijack Execution Flow
    
    # Memory safety issues
    'CWE-119': ['T1195', 'T1190'],  # Memory Corruption -> Supply Chain Compromise, Exploit Public-Facing App
    'CWE-120': ['T1190', 'T1195'],  # Buffer Overflow -> Exploit Public-Facing App, Supply Chain Compromise
    'CWE-125': ['T1190'],  # Out-of-bounds Read -> Exploit Public-Facing Application
    'CWE-416': ['T1190'],  # Use After Free -> Exploit Public-Facing Application
    
    # Web-specific issues
    'CWE-352': ['T1185'],  # CSRF -> Browser Session Hijacking
    'CWE-601': ['T1185'],  # Open Redirect -> Browser Session Hijacking
    
    # Cryptographic issues
    'CWE-327': ['T1558', 'T1557'],  # Broken/Risky Crypto -> Steal or Forge Kerberos Tickets, Man-in-the-Middle
    'CWE-295': ['T1557', 'T1539'],  # Certificate Validation -> Man-in-the-Middle, Steal Web Session Cookie
    
    # Default
    'CWE-0': ['T1190']  # Undefined/missing CWE -> Exploit Public-Facing Application
}

def create_vuln_attack_mappings():
    """
    Create mappings between vulnerabilities and ATT&CK techniques.
    This function analyzes vulnerability data and maps it to ATT&CK techniques
    using CWE mappings, description keywords, and other heuristics.
    """
    # Initialize database connection
    db = VulnerabilityDatabase()
    
    # Get all vulnerabilities
    vulnerabilities = db.get_all_vulnerabilities_with_cwe()
    
    # Get all ATT&CK techniques
    techniques = db.get_all_attack_techniques()
    
    # Create mapping table
    technique_dict = {t['technique_id']: t for t in techniques}
    mappings = []
    
    # Process each vulnerability
    for vuln in vulnerabilities:
        vuln_id = vuln['id']
        cwes = vuln.get('cwe', [])
        description = vuln.get('description', '')
        
        # Method 1: Map via CWEs
        for cwe in cwes:
            if cwe in CWE_ATTACK_MAPPINGS:
                for technique_id in CWE_ATTACK_MAPPINGS[cwe]:
                    if technique_id in technique_dict:
                        mappings.append({
                            'vuln_id': vuln_id,
                            'technique_id': technique_id,
                            'mapping_type': 'cwe_mapping',
                            'confidence': 0.7  # Medium-high confidence
                        })
        
        # Method 2: Look for technique keywords in description
        if description:
            for technique_id, technique in technique_dict.items():
                # Remove "T" prefix for matching (e.g., T1059 -> 1059)
                technique_num = technique_id[1:]
                
                # Look for direct references to the technique ID or name in the description
                if f"ATT&CK {technique_id}" in description or \
                   f"MITRE {technique_id}" in description or \
                   f"technique {technique_id}" in description or \
                   f"technique {technique_num}" in description:
                    mappings.append({
                        'vuln_id': vuln_id,
                        'technique_id': technique_id,
                        'mapping_type': 'explicit_reference',
                        'confidence': 0.9  # High confidence
                    })
                
                # Check if technique name is in description
                if technique['name'].lower() in description.lower():
                    mappings.append({
                        'vuln_id': vuln_id,
                        'technique_id': technique_id,
                        'mapping_type': 'description_keyword',
                        'confidence': 0.6  # Medium confidence
                    })
    
    # Save mappings to database
    print(f"Found {len(mappings)} potential vulnerability-to-ATT&CK mappings")
    inserted = 0
    
    for mapping in mappings:
        if db.insert_vulnerability_attack_mapping(mapping):
            inserted += 1
    
    print(f"Successfully inserted {inserted} vulnerability-ATT&CK mappings")
    
    # Close database connection
    db.close()

if __name__ == "__main__":
    create_vuln_attack_mappings()