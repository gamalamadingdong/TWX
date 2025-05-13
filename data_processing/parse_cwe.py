import xml.etree.ElementTree as ET

def get_element_text(element):
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
    
    return text

def parse_cwe_xml(cwe_xml_path):
    tree = ET.parse(cwe_xml_path)
    root = tree.getroot()
    namespace = {'cwe': 'http://cwe.mitre.org/cwe-7'}

    cwe_entries = []

    for weakness in root.findall(".//cwe:Weakness", namespace):
        cwe_id = f"CWE-{weakness.get('ID')}"
        name = weakness.get('Name')
        description = weakness.findtext('cwe:Description', default='', namespaces=namespace)
        extended_description = weakness.findtext('cwe:Extended_Description', default='', namespaces=namespace)
        category = weakness.get('Abstraction', '')

        mitigations = []
        for mitigation in weakness.findall(".//cwe:Potential_Mitigations/cwe:Mitigation/cwe:Description", namespace):
            # Use the helper function to extract all text content
            mitigation_text = get_element_text(mitigation).strip()
            if mitigation_text:
                mitigations.append(mitigation_text)
            # Remove debugging print statement
        
        mitigations_text = "; ".join(mitigations)

        cwe_entries.append({
            'cwe_id': cwe_id,
            'name': name,
            'description': description,
            'extended_description': extended_description,
            'category': category,
            'mitigations': mitigations_text
        })

    return cwe_entries