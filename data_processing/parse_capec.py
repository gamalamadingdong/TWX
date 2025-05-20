"""
CAPEC XML Parser for TWX Project.

This module parses CAPEC (Common Attack Pattern Enumeration and Classification) XML data,
extracting attack patterns and their relationships to CWEs (Common Weakness Enumeration).
CAPEC acts as the bridge between vulnerabilities (represented by CVEs/CWEs) and 
attack techniques (represented by MITRE ATT&CK).

This supports TWX's goal of unbiasing vulnerability data through proper classification
by establishing clear relationships between weaknesses and attack patterns.
"""

import os
import json
import logging
import xml.etree.ElementTree as ET
import re
from typing import Dict, List, Any
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def get_element_text(element) -> str:
    """Extract text from an XML element, handling None gracefully."""
    if element is None:
        return ""
    
    # Get direct text content
    text = element.text or ""
    
    # Also get text from child elements (for elements with mixed content)
    for child in element:
        if child.tail:
            text += child.tail
    
    return text.strip()

def extract_related_cwes(attack_pattern, namespace) -> List[str]:
    """
    Extract CWEs related to this attack pattern.
    
    Args:
        attack_pattern: XML element for a CAPEC attack pattern
        namespace: XML namespace dict
    
    Returns:
        List of CWE IDs (formatted as "CWE-XXX")
    """
    related_cwes = []
    
    # Check direct CWE references in Related_Weaknesses section
    for weakness in attack_pattern.findall(".//capec:Related_Weaknesses/capec:Related_Weakness", namespace):
        cwe_id = weakness.get('CWE_ID')
        if cwe_id:
            related_cwes.append(f"CWE-{cwe_id}")
    
    # Also check the Description for CWE references (for older CAPEC entries)
    description = get_element_text(attack_pattern.find(".//capec:Description", namespace))
    if description:
        # Look for CWE references in text (e.g., "CWE-79", "CWE 79", etc.)
        cwe_refs = re.findall(r'CWE[-\s](\d+)', description)
        for cwe_num in cwe_refs:
            related_cwes.append(f"CWE-{cwe_num}")
    
    # Deduplicate
    return sorted(list(set(related_cwes)))

def extract_references(attack_pattern, namespace) -> List[Dict[str, str]]:
    """
    Extract reference information from a CAPEC attack pattern.
    
    Args:
        attack_pattern: XML element for a CAPEC attack pattern
        namespace: XML namespace dict
    
    Returns:
        List of reference dictionaries
    """
    references = []
    
    for ref_element in attack_pattern.findall(".//capec:References/capec:Reference", namespace):
        ref_id = ref_element.get('External_Reference_ID', '')
        ref_type = ref_element.get('Reference_Type', '')
        
        title = get_element_text(ref_element.find(".//capec:Title", namespace))
        url = get_element_text(ref_element.find(".//capec:URL", namespace))
        
        # Only include entries with titles or URLs
        if title or url:
            references.append({
                "id": ref_id,
                "type": ref_type,
                "title": title,
                "url": url
            })
    
    return references

def extract_mitigations(attack_pattern, namespace) -> List[str]:
    """
    Extract mitigation information from a CAPEC attack pattern.
    
    Args:
        attack_pattern: XML element for a CAPEC attack pattern
        namespace: XML namespace dict
    
    Returns:
        List of mitigation strings
    """
    mitigations = []
    
    # Extract from Solutions_and_Mitigations section
    for mitigation in attack_pattern.findall(".//capec:Solutions_and_Mitigations/capec:Solution_or_Mitigation", namespace):
        text = get_element_text(mitigation)
        if text:
            mitigations.append(text)
    
    return mitigations

def extract_attack_steps(attack_pattern, namespace) -> List[Dict[str, str]]:
    """
    Extract execution flow/attack steps from a CAPEC attack pattern.
    
    Args:
        attack_pattern: XML element for a CAPEC attack pattern
        namespace: XML namespace dict
    
    Returns:
        List of attack step dictionaries
    """
    attack_steps = []
    
    # Try Execution_Flow (newer CAPEC)
    for step in attack_pattern.findall(".//capec:Execution_Flow/capec:Attack_Step", namespace):
        step_id = step.get('Step_ID', '')
        phase = step.get('Phase', '')
        
        description = get_element_text(step.find(".//capec:Description", namespace))
        technique = get_element_text(step.find(".//capec:Technique", namespace))
        
        if description or technique:
            attack_steps.append({
                "step_id": step_id,
                "phase": phase,
                "description": description,
                "technique": technique
            })
    
    # Try Attack_Phases (older CAPEC)
    if not attack_steps:
        for phase in attack_pattern.findall(".//capec:Attack_Phases/capec:Attack_Phase", namespace):
            phase_name = phase.get('Name', '')
            description = get_element_text(phase.find(".//capec:Description", namespace))
            
            if phase_name or description:
                attack_steps.append({
                    "phase": phase_name,
                    "description": description
                })
    
    return attack_steps

def extract_prerequisites(attack_pattern, namespace) -> List[str]:
    """Extract prerequisites for this attack pattern."""
    prerequisites = []
    
    for prereq in attack_pattern.findall(".//capec:Prerequisites/capec:Prerequisite", namespace):
        text = get_element_text(prereq)
        if text:
            prerequisites.append(text)
    
    return prerequisites

def extract_skills_required(attack_pattern, namespace) -> List[Dict[str, str]]:
    """Extract skills required for this attack pattern."""
    skills = []
    
    for skill in attack_pattern.findall(".//capec:Skills_Required/capec:Skill", namespace):
        level = skill.get('Level', '')
        text = get_element_text(skill)
        
        if text:
            skills.append({
                "level": level,
                "description": text
            })
    
    return skills

def extract_indicators(attack_pattern, namespace) -> List[str]:
    """Extract indicators for this attack pattern."""
    indicators = []
    
    for indicator in attack_pattern.findall(".//capec:Indicators/capec:Indicator", namespace):
        text = get_element_text(indicator)
        if text:
            indicators.append(text)
    
    return indicators

def extract_consequences(attack_pattern, namespace) -> List[Dict[str, str]]:
    """Extract consequences of this attack pattern."""
    consequences = []
    
    for consequence in attack_pattern.findall(".//capec:Consequences/capec:Consequence", namespace):
        scope = consequence.get('Scope', '')
        impact = consequence.get('Impact', '')
        note = get_element_text(consequence)
        
        consequences.append({
            "scope": scope,
            "impact": impact,
            "note": note
        })
    
    return consequences

def parse_capec_xml(xml_path="data_collection/raw_data/capec_data/capec_v3.9.xml", 
                   output_json="data_collection/raw_data/capec_data/capec.json",
                   output_mapping="data_collection/raw_data/mappings/cwe_capec.csv"):
    """
    Parse CAPEC XML file to create:
    1. A JSON file with all CAPEC data
    2. A CSV file mapping CWEs to CAPECs
    
    Args:
        xml_path: Path to CAPEC XML file
        output_json: Path to save JSON output
        output_mapping: Path to save CWE-CAPEC mapping CSV
        
    Returns:
        dict: Processed CAPEC data or False if failed
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
        
        # Get CAPEC version information
        version = "unknown"
        date = "unknown"
        
        # Try to extract version info from different places
        version_info = root.find(".//capec:Version", ns)
        if version_info is not None:
            version = get_element_text(version_info)
            
        date_info = root.find(".//capec:Date", ns)
        if date_info is not None:
            date = get_element_text(date_info)
        
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
            name = get_element_text(ap.find(".//capec:Name", ns))
            summary = get_element_text(ap.find(".//capec:Summary", ns))
            description = get_element_text(ap.find(".//capec:Description", ns))
            abstraction = ap.get('Abstraction', '')
            status = ap.get('Status', '')
            
            # Likelihood values
            likelihood = ap.get('Likelihood_Of_Attack', '')
            typical_severity = ap.get('Typical_Severity', '')
            
            # Extract related weaknesses (CWEs)
            related_cwes = extract_related_cwes(ap, ns)
            
            # Add to mappings list
            for cwe_id in related_cwes:
                cwe_capec_mappings.append((cwe_id, capec_id))
            
            # Extract other detailed information
            references = extract_references(ap, ns)
            mitigations = extract_mitigations(ap, ns)
            attack_steps = extract_attack_steps(ap, ns)
            prerequisites = extract_prerequisites(ap, ns)
            skills_required = extract_skills_required(ap, ns)
            indicators = extract_indicators(ap, ns)
            consequences = extract_consequences(ap, ns)
            
            # Build comprehensive attack pattern object
            attack_pattern = {
                "id": pattern_id,
                "capec_id": capec_id,
                "name": name,
                "summary": summary,
                "description": description,
                "abstraction": abstraction,
                "status": status,
                "likelihood": likelihood,
                "severity": typical_severity,
                "related_weaknesses": related_cwes,
                "attack_steps": attack_steps,
                "prerequisites": prerequisites,
                "skills_required": skills_required,
                "mitigations": mitigations,
                "indicators": indicators,
                "consequences": consequences,
                "references": references
            }
            
            attack_patterns.append(attack_pattern)
        
        # Create JSON structure
        capec_json = {
            "attack_patterns": attack_patterns,
            "version": version,
            "date": date,
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
        
        return capec_json
        
    except Exception as e:
        logger.error(f"Error parsing CAPEC XML: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_parser(xml_path=None):
    """Test the parser with a specific CAPEC XML file."""
    if xml_path is None:
        # Try to find a CAPEC XML file in the default location
        default_dir = "data_collection/raw_data/capec_data"
        if os.path.exists(default_dir):
            xml_files = list(Path(default_dir).glob("capec_v*.xml"))
            if xml_files:
                xml_path = str(sorted(xml_files)[-1])
    
    if xml_path is None or not os.path.exists(xml_path):
        logger.error("No CAPEC XML file found for testing")
        return
    
    logger.info(f"Testing CAPEC parser with {xml_path}")
    result = parse_capec_xml(xml_path)
    
    if result:
        # Display some statistics
        pattern_count = len(result["attack_patterns"])
        logger.info(f"Successfully parsed {pattern_count} CAPEC attack patterns")
        
        # Show a sample of parsed patterns
        sample_size = min(5, pattern_count)
        logger.info(f"Sample of {sample_size} parsed patterns:")
        
        for i, pattern in enumerate(result["attack_patterns"][:sample_size]):
            logger.info(f"{i+1}. {pattern['capec_id']}: {pattern['name']}")
            logger.info(f"   Summary: {pattern['summary'][:100]}...")
            logger.info(f"   Related CWEs: {', '.join(pattern['related_weaknesses'])}")
            logger.info(f"   Severity: {pattern['severity']}")
            logger.info(f"   Likelihood: {pattern['likelihood']}")
            logger.info("   " + "-" * 40)
    
        return result
    else:
        logger.error("Parser test failed")
        return None

if __name__ == "__main__":
    # If run directly, test the parser
    test_parser()