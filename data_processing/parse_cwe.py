"""
Enhanced CWE parser for the TWX project.

This parser extracts comprehensive information from CWE XML files, including:
1. Core weakness details (ID, name, description)
2. Relationships between weaknesses (parent/child, related)
3. Potential consequences and their impacts
4. Real-world examples and exploitation methods
5. Detection methods and mitigations
6. Related CAPEC attack patterns for mapping to ATT&CK
"""

import xml.etree.ElementTree as ET
import re
from typing import List, Dict, Any, Optional
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def get_element_text(element) -> str:
    """Extract all text from an element and its children recursively."""
    if element is None:
        return ""
    
    # Start with the element's own text
    text = element.text or ""
    
    # Add text from all child elements
    for child in element:
        text += get_element_text(child)
        # Add any tail text (text that comes after the child)
        if child.tail:
            text += child.tail
    
    return text.strip()

def extract_relationships(weakness, namespace) -> Dict[str, List[str]]:
    """Extract relationships between this weakness and other CWEs."""
    relationships = {
        "parents": [],       # CWEs this one specializes from
        "children": [],      # CWEs that specialize from this one
        "requires": [],      # CWEs required by this one
        "required_by": [],   # CWEs that require this one
        "canPrecede": [],    # CWEs that can follow this one
        "canFollow": [],     # CWEs that can precede this one
        "peers": [],         # Related CWEs at same level of abstraction
        "alternatives": []   # Alternative CWE perspectives
    }

    # Map XML relation names to our simplified categories
    relationship_mapping = {
        'ChildOf': 'parents',
        'ParentOf': 'children',
        'RequiredBy': 'required_by',
        'Requires': 'requires',
        'CanPrecede': 'canPrecede',
        'CanFollow': 'canFollow',
        'PeerOf': 'peers',
        'MemberOf': 'parents',  # MemberOf often indicates a category parent
        'CanAlsoBe': 'alternatives'
    }

    # Extract relationships from the Related_Weaknesses section
    for related in weakness.findall(".//cwe:Related_Weaknesses/cwe:Related_Weakness", namespace):
        nature = related.get('Nature', '')
        cwe_id = f"CWE-{related.get('CWE_ID', '')}"
        view_id = related.get('View_ID', '')
        
        # Skip relationships to views rather than weaknesses
        if view_id:
            continue
            
        if nature in relationship_mapping:
            category = relationship_mapping[nature]
            if cwe_id not in relationships[category]:
                relationships[category].append(cwe_id)
    
    return relationships

def extract_consequences(weakness, namespace) -> List[Dict[str, str]]:
    """Extract detailed consequence information."""
    consequences = []
    
    for consequence in weakness.findall(".//cwe:Common_Consequences/cwe:Consequence", namespace):
        # Extract scope (impact areas)
        scopes = []
        for scope in consequence.findall(".//cwe:Scope", namespace):
            if scope.text:
                scopes.append(scope.text.strip())
        
        # Extract impact
        impacts = []
        for impact in consequence.findall(".//cwe:Impact", namespace):
            if impact.text:
                impacts.append(impact.text.strip())
                
        # Extract note/description
        note = ""
        note_element = consequence.find(".//cwe:Note", namespace)
        if note_element is not None:
            note = get_element_text(note_element)
        
        # Format and add to list
        if scopes or impacts:
            consequences.append({
                "scope": ", ".join(scopes),
                "impact": ", ".join(impacts),
                "note": note
            })
    
    return consequences

def extract_detection_methods(weakness, namespace) -> List[Dict[str, str]]:
    """Extract methods for detecting this weakness."""
    detection_methods = []
    
    for detection in weakness.findall(".//cwe:Detection_Methods/cwe:Detection_Method", namespace):
        method_name = detection.get('Method')
        
        # Extract description
        description = ""
        desc_element = detection.find(".//cwe:Description", namespace)
        if desc_element is not None:
            description = get_element_text(desc_element)
            
        # Extract effectiveness
        effectiveness = detection.get('Effectiveness')
        
        if method_name or description:
            detection_methods.append({
                "method": method_name,
                "description": description,
                "effectiveness": effectiveness
            })
    
    return detection_methods

def extract_mitigations(weakness, namespace) -> List[Dict[str, str]]:
    """Extract detailed mitigation information."""
    mitigations = []
    
    for mitigation in weakness.findall(".//cwe:Potential_Mitigations/cwe:Mitigation", namespace):
        # Extract phase (when this mitigation should be applied)
        phases = []
        for phase in mitigation.findall(".//cwe:Phase", namespace):
            if phase.text:
                phases.append(phase.text.strip())
        
        # Extract strategy
        strategy = mitigation.findtext(".//cwe:Strategy", "", namespace)
        
        # Extract description using helper function to get all nested text
        description = ""
        desc_element = mitigation.find(".//cwe:Description", namespace)
        if desc_element is not None:
            description = get_element_text(desc_element)
        
        # Extract effectiveness and notes
        effectiveness = mitigation.get('Effectiveness')
        
        if description:
            mitigations.append({
                "phases": ", ".join(phases),
                "strategy": strategy,
                "description": description,
                "effectiveness": effectiveness
            })
    
    return mitigations

def extract_attack_patterns(weakness, namespace) -> List[str]:
    """Extract CAPEC attack patterns related to this weakness."""
    attack_patterns = []
    
    # First check directly referenced CAPECs
    for related_attack_pattern in weakness.findall(".//cwe:Related_Attack_Patterns/cwe:Related_Attack_Pattern", namespace):
        capec_id = related_attack_pattern.get('CAPEC_ID')
        if capec_id:
            attack_patterns.append(f"CAPEC-{capec_id}")
    
    return attack_patterns

def extract_examples(weakness, namespace) -> List[Dict[str, str]]:
    """Extract real-world examples and demonstration code."""
    examples = []
    
    for example in weakness.findall(".//cwe:Observed_Examples/cwe:Observed_Example", namespace):
        reference = example.findtext(".//cwe:Reference", "", namespace)
        description = example.findtext(".//cwe:Description", "", namespace)
        cve_id = ""
        
        # Try to extract a CVE ID if present
        if reference:
            cve_match = re.search(r'CVE-\d{4}-\d{4,}', reference)
            if cve_match:
                cve_id = cve_match.group(0)
        
        if description:
            examples.append({
                "reference": reference,
                "description": description,
                "cve_id": cve_id
            })
    
    # Also extract demonstrative examples (code)
    for demo in weakness.findall(".//cwe:Demonstrative_Examples/cwe:Demonstrative_Example", namespace):
        title = demo.get('Name', '')
        
        # Extract the example code and explanations
        intro = ""
        intro_element = demo.find(".//cwe:Intro", namespace)
        if intro_element is not None:
            intro = get_element_text(intro_element)
        
        # Combine all code snippets
        code_snippets = []
        for snippet in demo.findall(".//cwe:Example_Code", namespace):
            language = snippet.get('Nature', '')
            code = get_element_text(snippet)
            if code:
                code_snippets.append({
                    "language": language,
                    "code": code
                })
        
        # Get explanation
        explanation = ""
        explanation_element = demo.find(".//cwe:Description", namespace)
        if explanation_element is not None:
            explanation = get_element_text(explanation_element)
        
        if title or intro or code_snippets or explanation:
            examples.append({
                "type": "demonstration",
                "title": title,
                "introduction": intro,
                "code_snippets": code_snippets,
                "explanation": explanation
            })
    
    return examples

def extract_likelihood(weakness, namespace) -> Dict[str, str]:
    """Extract likelihood and exploitability information."""
    likelihood_info = {}
    
    # Extract likelihood of exploit
    likelihood = weakness.findtext(".//cwe:Likelihood_Of_Exploit", "", namespace)
    if likelihood:
        likelihood_info["likelihood_of_exploit"] = likelihood
    
    return likelihood_info

def parse_cwe_xml(cwe_xml_path: str) -> List[Dict[str, Any]]:
    """
    Parse CWE XML file and extract comprehensive weakness information.
    
    Args:
        cwe_xml_path: Path to the CWE XML file
        
    Returns:
        List of dictionaries containing CWE data
    """
    try:
        logger.info(f"Parsing CWE XML file: {cwe_xml_path}")
        
        # Use a more robust XML parsing approach
        try:
            tree = ET.parse(cwe_xml_path)
            root = tree.getroot()
        except ET.ParseError as e:
            logger.error(f"XML parsing error: {e}. Trying with more lenient parsing...")
            # Sometimes XML files have formatting issues, try a more lenient approach
            with open(cwe_xml_path, 'r', encoding='utf-8') as f:
                xml_content = f.read()
                # Remove problematic characters
                xml_content = re.sub(r'&(?!amp;|lt;|gt;|apos;|quot;)', '&amp;', xml_content)
                root = ET.fromstring(xml_content)
        
        # Extract namespace from the root element
        # This is more robust than hardcoding the namespace
        namespace = {'cwe': root.tag.split('}')[0].strip('{')} if '}' in root.tag else {'cwe': 'http://cwe.mitre.org/cwe-7'}
        logger.info(f"Detected XML namespace: {namespace['cwe']}")

        # Get CWE version and date from catalog metadata
        catalog = root.find(".//cwe:Catalog", namespace) or root.find(".//Catalog")
        cwe_version = "Unknown"
        cwe_date = "Unknown"
        if catalog is not None:
            cwe_version = catalog.get('Version', 'Unknown')
            cwe_date = catalog.get('Date', 'Unknown')
        
        logger.info(f"Processing CWE data version {cwe_version} ({cwe_date})")
        
        cwe_entries = []
        count = 0
        
        # Find all weakness elements, trying different XPaths in case namespace is different
        weaknesses = root.findall(".//cwe:Weakness", namespace) or root.findall(".//Weakness")
        
        if not weaknesses:
            logger.warning("No weakness elements found in the XML file. Check if the XML structure matches expectations.")
            return []
            
        logger.info(f"Found {len(weaknesses)} weakness entries in XML file")
        
        # Process weaknesses
        for weakness in weaknesses:
            try:
                # Extract core weakness data safely
                cwe_id = f"CWE-{weakness.get('ID', '')}"
                if not cwe_id or cwe_id == "CWE-":
                    logger.debug(f"Skipping weakness with no ID")
                    continue
                    
                name = weakness.get('Name', '')
                abstraction = weakness.get('Abstraction', '')
                status = weakness.get('Status', '')
                
                # Extract description fields
                description_elem = weakness.find(".//cwe:Description", namespace) or weakness.find(".//Description")
                description = get_element_text(description_elem) if description_elem is not None else ""
                
                extended_desc_elem = weakness.find(".//cwe:Extended_Description", namespace) or weakness.find(".//Extended_Description")
                extended_description = get_element_text(extended_desc_elem) if extended_desc_elem is not None else ""
                
                # Create the basic CWE entry
                cwe_entry = {
                    'cwe_id': cwe_id,
                    'name': name,
                    'description': description,
                    'extended_description': extended_description,
                    'abstraction': abstraction,
                    'status': status,
                    'relationships': extract_relationships(weakness, namespace),
                    'consequences': extract_consequences(weakness, namespace),
                    'detection_methods': extract_detection_methods(weakness, namespace),
                    'mitigations': extract_mitigations(weakness, namespace),
                    'mitigations_text': "", # Will populate below
                    'attack_patterns': extract_attack_patterns(weakness, namespace),
                    'examples': extract_examples(weakness, namespace),
                    'likelihood': ""
                }
                
                # Populate mitigations_text field
                mitigations = cwe_entry['mitigations']
                if mitigations:
                    cwe_entry['mitigations_text'] = "; ".join([m.get("description", "") for m in mitigations if "description" in m])
                
                # Extract high-level category for classification
                cwe_entry['category'] = determine_cwe_category(cwe_id, cwe_entry['relationships'], name, description)
                
                cwe_entries.append(cwe_entry)
                count += 1
                
                if count % 100 == 0:
                    logger.info(f"Processed {count} CWEs")
                
            except Exception as e:
                logger.error(f"Error processing CWE {weakness.get('ID', 'unknown')}: {str(e)}")
                logger.debug(f"Exception details:", exc_info=True)
        
        logger.info(f"Successfully parsed {len(cwe_entries)} CWE entries")
        return cwe_entries
        
    except Exception as e:
        logger.error(f"Failed to parse CWE XML file: {str(e)}")
        logger.debug("Exception details:", exc_info=True)
        return []

def determine_cwe_category(cwe_id: str, relationships: Dict, name: str, description: str) -> str:
    """Determine a high-level category for the CWE based on its ID, relationships, and content."""
    # Common CWE groupings relevant for classification
    cwe_categories = {
        # Memory safety
        "Memory Safety": ["CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-125", 
                         "CWE-416", "CWE-476", "CWE-787"],
        # Injection
        "Injection": ["CWE-74", "CWE-77", "CWE-78", "CWE-79", "CWE-80", 
                     "CWE-83", "CWE-89", "CWE-564", "CWE-917"],
        # Access Control
        "Access Control": ["CWE-22", "CWE-264", "CWE-269", "CWE-275", "CWE-284", 
                          "CWE-285", "CWE-287", "CWE-306", "CWE-732"],
        # Cryptographic Issues
        "Cryptographic Issues": ["CWE-295", "CWE-310", "CWE-320", "CWE-321", "CWE-326", 
                                "CWE-327", "CWE-329", "CWE-330"],
        # Information Disclosure                      
        "Information Disclosure": ["CWE-200", "CWE-203", "CWE-209", "CWE-532", "CWE-538"],
    }
    
    # Check if this CWE belongs to any of these categories
    for category_name, cwe_list in cwe_categories.items():
        if any(cwe_id == cid for cid in cwe_list):
            return category_name
    
    # Keywords in name or description for additional categorization
    if re.search(r'injection|xss|cross-site', name.lower() + ' ' + description.lower()):
        return "Injection"
    elif re.search(r'buffer|memory|overflow|null pointer|use after free', name.lower() + ' ' + description.lower()):
        return "Memory Safety"
    elif re.search(r'access control|permission|privilege|auth[a-z]*|directory traversal', name.lower() + ' ' + description.lower()):
        return "Access Control"
    elif re.search(r'crypt[a-z]*|cipher|encrypt|decrypt|key|hash', name.lower() + ' ' + description.lower()):
        return "Cryptographic Issues"
    elif re.search(r'disclose|leak|expose|sensitive|information', name.lower() + ' ' + description.lower()):
        return "Information Disclosure"
    
    # Default category
    return "Other"
def extract_cwe_categories(cwe_entries: List[Dict]) -> Dict[str, Dict]:
    """
    Organize CWEs by category to support classification.
    
    Args:
        cwe_entries: List of parsed CWE entries
        
    Returns:
        Dictionary mapping categories to information about that category
    """
    # Create structured categories
    categories = {
        "Memory Safety": {
            "description": "Vulnerabilities related to memory management and access",
            "cwe_ids": [],
            "subcategories": {
                "Buffer Overflows": [],
                "Memory Leaks": [],
                "Use After Free": [],
                "Double Free": [],
                "Null Pointer Dereference": []
            }
        },
        "Injection": {
            "description": "Vulnerabilities allowing code or data injection",
            "cwe_ids": [],
            "subcategories": {
                "SQL Injection": [],
                "Command Injection": [],
                "Cross-site Scripting": [],
                "LDAP Injection": [],
                "XML Injection": [],
                "Format String": []
            }
        },
        "Access Control": {
            "description": "Vulnerabilities affecting authorization and permissions",
            "cwe_ids": [],
            "subcategories": {
                "Missing Authorization": [],
                "Broken Authentication": [],
                "Path Traversal": [],
                "Privilege Escalation": [],
                "Incorrect Permissions": []
            }
        },
        "Cryptographic Issues": {
            "description": "Vulnerabilities in cryptographic implementation or usage",
            "cwe_ids": [],
            "subcategories": {
                "Weak Encryption": [],
                "Insufficient Entropy": [],
                "Broken Algorithms": [],
                "Key Management": [],
                "Certificate Validation": []
            }
        },
        "Information Disclosure": {
            "description": "Vulnerabilities leading to unauthorized data exposure",
            "cwe_ids": [],
            "subcategories": {
                "Sensitive Data Exposure": [],
                "Information Leakage": [],
                "Debug Information": [],
                "Error Messages": []
            }
        },
        "Input Validation": {
            "description": "Vulnerabilities due to insufficient input handling",
            "cwe_ids": [],
            "subcategories": {
                "Missing Validation": [],
                "Incorrect Input Handling": [],
                "Type Confusion": []
            }
        },
        "Resource Management": {
            "description": "Vulnerabilities in managing system resources",
            "cwe_ids": [],
            "subcategories": {
                "Race Conditions": [],
                "Deadlocks": [],
                "Denial of Service": [],
                "Uncontrolled Resource Consumption": []
            }
        },
        "Insecure Design": {
            "description": "Vulnerabilities due to flawed design rather than implementation",
            "cwe_ids": [],
            "subcategories": {
                "Missing Security Controls": [],
                "Unsafe Defaults": [],
                "Trust Boundary Violations": []
            }
        },
        "Time and State": {
            "description": "Vulnerabilities related to timing and state management",
            "cwe_ids": [],
            "subcategories": {
                "TOCTOU": [],
                "Session Management": [],
                "Race Conditions": []
            }
        }
    }
    
    # Specific CWE mappings to categories and subcategories
    specific_mappings = {
        # Memory Safety
        "CWE-119": ("Memory Safety", "Buffer Overflows"),
        "CWE-120": ("Memory Safety", "Buffer Overflows"),
        "CWE-122": ("Memory Safety", "Buffer Overflows"),
        "CWE-125": ("Memory Safety", "Buffer Overflows"),
        "CWE-787": ("Memory Safety", "Buffer Overflows"),
        "CWE-416": ("Memory Safety", "Use After Free"),
        "CWE-415": ("Memory Safety", "Double Free"),
        "CWE-476": ("Memory Safety", "Null Pointer Dereference"),
        
        # Injection
        "CWE-89": ("Injection", "SQL Injection"),
        "CWE-564": ("Injection", "SQL Injection"),
        "CWE-77": ("Injection", "Command Injection"),
        "CWE-78": ("Injection", "Command Injection"),
        "CWE-79": ("Injection", "Cross-site Scripting"),
        "CWE-80": ("Injection", "Cross-site Scripting"),
        "CWE-83": ("Injection", "Cross-site Scripting"),
        "CWE-91": ("Injection", "XML Injection"),
        "CWE-643": ("Injection", "XML Injection"),
        "CWE-90": ("Injection", "LDAP Injection"),
        "CWE-134": ("Injection", "Format String"),
        
        # Access Control
        "CWE-284": ("Access Control", "Missing Authorization"),
        "CWE-285": ("Access Control", "Missing Authorization"),
        "CWE-287": ("Access Control", "Broken Authentication"),
        "CWE-306": ("Access Control", "Broken Authentication"),
        "CWE-22": ("Access Control", "Path Traversal"),
        "CWE-23": ("Access Control", "Path Traversal"),
        "CWE-36": ("Access Control", "Path Traversal"),
        "CWE-269": ("Access Control", "Privilege Escalation"),
        "CWE-732": ("Access Control", "Incorrect Permissions"),
        
        # Cryptographic Issues
        "CWE-327": ("Cryptographic Issues", "Weak Encryption"),
        "CWE-328": ("Cryptographic Issues", "Weak Encryption"),
        "CWE-326": ("Cryptographic Issues", "Insufficient Entropy"),
        "CWE-330": ("Cryptographic Issues", "Insufficient Entropy"),
        "CWE-295": ("Cryptographic Issues", "Certificate Validation"),
        "CWE-320": ("Cryptographic Issues", "Key Management"),
        
        # Information Disclosure
        "CWE-200": ("Information Disclosure", "Sensitive Data Exposure"),
        "CWE-532": ("Information Disclosure", "Information Leakage"),
        "CWE-209": ("Information Disclosure", "Error Messages"),
        "CWE-538": ("Information Disclosure", "Debug Information"),
        
        # Input Validation
        "CWE-20": ("Input Validation", "Missing Validation"),
        "CWE-116": ("Input Validation", "Incorrect Input Handling"),
        "CWE-843": ("Input Validation", "Type Confusion"),
        
        # Resource Management
        "CWE-400": ("Resource Management", "Uncontrolled Resource Consumption"),
        "CWE-362": ("Resource Management", "Race Conditions"),
        "CWE-833": ("Resource Management", "Deadlocks"),
        "CWE-404": ("Resource Management", "Resource Leaks"),
        
        # Insecure Design
        "CWE-1173": ("Insecure Design", "Missing Security Controls"),
        "CWE-636": ("Insecure Design", "Unsafe Defaults"),
        "CWE-501": ("Insecure Design", "Trust Boundary Violations"),
        
        # Time and State
        "CWE-367": ("Time and State", "TOCTOU"),
        "CWE-613": ("Time and State", "Session Management"),
        "CWE-384": ("Time and State", "Session Management"),
    }
    
    # Map CWEs to our categories based on the specific mappings
    for entry in cwe_entries:
        cwe_id = entry.get('cwe_id')
        if cwe_id in specific_mappings:
            category, subcategory = specific_mappings[cwe_id]
            if cwe_id not in categories[category]["cwe_ids"]:
                categories[category]["cwe_ids"].append(cwe_id)
            if cwe_id not in categories[category]["subcategories"][subcategory]:
                categories[category]["subcategories"][subcategory].append(cwe_id)
        
    # Process the CWE entries and add to appropriate category
    for entry in cwe_entries:
        cwe_id = entry.get('cwe_id')
        name = entry.get('name', '').lower()
        desc = entry.get('description', '').lower()
        
        # If already categorized in a specific mapping, skip
        if cwe_id in specific_mappings:
            continue
            
        # Try to categorize based on name and description keywords
        categorized = False
        
        # Try to categorize by keywords in name/description
        keyword_to_category = {
            "memory|buffer|overflow|underflow|out-of-bounds|free|heap|stack|allocation": "Memory Safety",
            "injection|sql|command|xss|cross-site|script|format string|template|ldap": "Injection",
            "access|permission|privilege|authorization|authentication|session|csrf|trust|boundary": "Access Control",
            "crypt|encrypt|decrypt|cipher|hash|salt|random|prng|key|certificate": "Cryptographic Issues",
            "information disclosure|information exposure|sensitive|leak|confidential": "Information Disclosure",
            "validation|sanitization|filter|escape|normalize|input": "Input Validation",
            "race condition|time of check|deadlock|resource|consumption|exhaustion|denial": "Resource Management",
            "design|insecure default|misconfiguration|unsafe": "Insecure Design",
            "toctou|time of check|session|state": "Time and State"
        }
        
        text_to_search = f"{name} {desc}"
        for pattern, category in keyword_to_category.items():
            if re.search(pattern, text_to_search, re.IGNORECASE):
                categories[category]["cwe_ids"].append(cwe_id)
                categorized = True
                break
                
        # If still not categorized, try using CWE abstraction and structure
        if not categorized:
            if entry.get("abstraction") == "Base":
                # Look at parent relationships to infer category
                parents = entry.get('relationships', {}).get('parents', [])
                for parent_id in parents:
                    # Check if parent is in a known category
                    for category, info in categories.items():
                        if parent_id in info["cwe_ids"]:
                            if cwe_id not in info["cwe_ids"]:
                                info["cwe_ids"].append(cwe_id)
                            categorized = True
                            break
                    if categorized:
                        break
    
    return categories

def export_cwe_categories(cwe_entries: List[Dict], output_path: str = "analysis/cwe_categories.json"):
    """Export CWE categories to a JSON file for classification."""
    import json
    import os
    
    categories = extract_cwe_categories(cwe_entries)
    
    # Make directory if it doesn't exist
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    with open(output_path, 'w') as f:
        json.dump(categories, f, indent=2)
    
    logger.info(f"Exported CWE categories to {output_path}")
    return categories

if __name__ == "__main__":
    # Example usage
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python parse_cwe.py <cwe_xml_path> [output_json_path]")
        sys.exit(1)
    
    cwe_xml_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else "analysis/cwe_data.json"
    
    cwe_entries = parse_cwe_xml(cwe_xml_path)
    
    # Export to JSON
    import json
    import os
    
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    with open(output_path, 'w') as f:
        json.dump(cwe_entries, f, indent=2)
        
    print(f"Exported {len(cwe_entries)} CWE entries to {output_path}")
    
    # Also export categories
    categories = export_cwe_categories(cwe_entries)
    print(f"Created {len(categories)} CWE categories")