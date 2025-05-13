import json
import os
import sys

def extract_attack_techniques(attack_data):
    """
    Extract ATT&CK techniques from raw data.
    
    Args:
        attack_data: Raw ATT&CK data
        
    Returns:
        list: List of technique objects
    """
    techniques = []
    
    # Process objects from the bundle
    for obj in attack_data.get('objects', []):
        # We're interested in attack-pattern objects
        if obj.get('type') == 'attack-pattern':
            # Extract technique ID (like 'T1059')
            technique_id = None
            for ref in obj.get('external_references', []):
                if ref.get('source_name') == 'mitre-attack':
                    technique_id = ref.get('external_id')
                    break
            
            if not technique_id:
                continue
                
            # Extract name and description
            name = obj.get('name', '')
            description = obj.get('description', '')
            
            # Extract tactic
            tactic = ''
            for kill_chain_phase in obj.get('kill_chain_phases', []):
                if kill_chain_phase.get('kill_chain_name') == 'mitre-attack':
                    tactic = kill_chain_phase.get('phase_name', '')
                    break
            
            # Create technique record
            technique = {
                'technique_id': technique_id,
                'name': name,
                'description': description,
                'tactic': tactic
            }
            
            techniques.append(technique)
    
    print(f"Extracted {len(techniques)} ATT&CK techniques")
    return techniques

def parse_attack_data(file_path):
    """
    Parse MITRE ATT&CK data file.
    
    Args:
        file_path: Path to the ATT&CK data file
        
    Returns:
        list: List of technique objects
    """
    try:
        print(f"Loading ATT&CK data from {file_path}")
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        techniques = extract_attack_techniques(data)
        return techniques
    
    except Exception as e:
        print(f"Error parsing ATT&CK data: {e}")
        import traceback
        traceback.print_exc()
        return []

if __name__ == "__main__":
    # Test the parser on a sample file
    import sys
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
    else:
        # Default path for testing
        file_path = "data_collection/raw_data/attack_data/enterprise-attack.json"
    
    techniques = parse_attack_data(file_path)
    print(f"Found {len(techniques)} techniques")
    
    # Print first 5 techniques as a sample
    for i, technique in enumerate(techniques[:5]):
        print(f"\nTechnique {i+1}:")
        for key, value in technique.items():
            if key == 'description':
                print(f"  {key}: {value[:100]}...")  # Truncate long descriptions
            else:
                print(f"  {key}: {value}")