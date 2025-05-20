"""
Test version of NVD parser that processes just a few records and prints detailed debug information
to diagnose the AttributeError issues.
"""

import json
import os
import sys
from pprint import pprint

def load_nvd_json(file_path):
    """Load NVD JSON data with error handling."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            print(f"Successfully loaded JSON from {file_path}")
            print(f"Top level keys: {list(data.keys())}")
            return data
    except Exception as e:
        print(f"Error loading NVD file {file_path}: {str(e)}")
        return None

def examine_nvd_structure(data):
    """Examine NVD data structure to understand format."""
    if not data:
        print("No data to examine")
        return
        
    # Check if this is a CVE_Items format or newer NVD API format
    if "CVE_Items" in data:
        print("Found legacy NVD format with CVE_Items")
        items = data["CVE_Items"]
        format_type = "legacy"
    elif "vulnerabilities" in data:
        print("Found newer NVD API format with vulnerabilities")
        items = data["vulnerabilities"]
        format_type = "new_api"
    else:
        print(f"Unknown NVD format. Available keys: {list(data.keys())}")
        return None, None
        
    print(f"Found {len(items)} vulnerability items")
    return items, format_type

def parse_single_item(item, format_type):
    """Parse a single NVD item with detailed logging."""
    try:
        # Get the CVE ID based on format
        if format_type == "legacy":
            cve_id = item.get("cve", {}).get("CVE_data_meta", {}).get("ID")
        else:  # new_api
            cve_id = item.get("cve", {}).get("id")
            
        print(f"\nProcessing item with CVE ID: {cve_id}")
        
        # Extract description based on format
        description = ""
        if format_type == "legacy":
            desc_data = item.get("cve", {}).get("description", {}).get("description_data", [])
            for desc in desc_data:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
        else:  # new_api
            descriptions = item.get("cve", {}).get("descriptions", [])
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
        
        print(f"Description: {description[:100]}..." if description else "No description found")
        
        # Extract CWE information
        cwes = []
        if format_type == "legacy":
            problem_type_data = item.get("cve", {}).get("problemtype", {}).get("problemtype_data", [])
            for problem in problem_type_data:
                for desc in problem.get("description", []):
                    if "value" in desc and "CWE" in desc.get("value", ""):
                        cwes.append(desc.get("value"))
        else:  # new_api
            vuln_data = item.get("cve", {})
            if "weaknesses" in vuln_data:
                for weakness in vuln_data["weaknesses"]:
                    for desc in weakness.get("description", []):
                        if "value" in desc and "CWE" in desc.get("value", ""):
                            cwes.append(desc.get("value"))
                            
        print(f"CWEs found: {cwes}")
        
        # Extract CVSS data
        cvss_data = {}
        if format_type == "legacy":
            impact = item.get("impact", {})
            if "baseMetricV3" in impact:
                cvss_v3 = impact.get("baseMetricV3", {}).get("cvssV3", {})
                if cvss_v3:
                    cvss_data = {
                        "version": "3.1" if cvss_v3.get("version") == "3.1" else "3.0",
                        "base_score": cvss_v3.get("baseScore"),
                        "base_severity": cvss_v3.get("baseSeverity", "")
                    }
        else:  # new_api
            metrics = item.get("cve", {}).get("metrics", {})
            if "cvssMetricV31" in metrics:
                cvss_v3 = metrics["cvssMetricV31"][0].get("cvssData", {}) if metrics["cvssMetricV31"] else {}
                if cvss_v3:
                    cvss_data = {
                        "version": "3.1",
                        "base_score": cvss_v3.get("baseScore"),
                        "base_severity": cvss_v3.get("baseSeverity", "")
                    }
            elif "cvssMetricV30" in metrics:
                cvss_v3 = metrics["cvssMetricV30"][0].get("cvssData", {}) if metrics["cvssMetricV30"] else {}
                if cvss_v3:
                    cvss_data = {
                        "version": "3.0",
                        "base_score": cvss_v3.get("baseScore"),
                        "base_severity": cvss_v3.get("baseSeverity", "")
                    }
                    
        print(f"CVSS data: {cvss_data}")
        
        # Create a normalized record
        normalized_record = {
            "id": cve_id,
            "description": description,
            "cwe": cwes,
            "cvss": cvss_data
        }
        
        # Add configurations/products information if needed
        # We'll omit this for now to keep things simple
        
        print("Successfully parsed item")
        return normalized_record
        
    except Exception as e:
        print(f"Error parsing item: {str(e)}")
        import traceback
        traceback.print_exc()
        return {"id": cve_id if 'cve_id' in locals() else "unknown", "parse_error": str(e)}

def test_nvd_parser(file_path, limit=5):
    """Test NVD parser on a limited number of records."""
    print(f"Testing NVD parser on {file_path}")
    data = load_nvd_json(file_path)
    if not data:
        return []
        
    items, format_type = examine_nvd_structure(data)
    if not items:
        return []
    
    parsed_records = []
    for i, item in enumerate(items[:limit]):
        print(f"\n--- Processing item {i+1}/{min(limit, len(items))} ---")
        parsed = parse_single_item(item, format_type)
        if parsed:
            parsed_records.append(parsed)
    
    print(f"\nSuccessfully parsed {len(parsed_records)} records")
    return parsed_records

if __name__ == "__main__":
    # Check if file path is provided as argument
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
    else:
        # Try to find a suitable NVD file
        data_dir = "data_collection/raw_data/nvd_data"
        files = [f for f in os.listdir(data_dir) if f.endswith('.json')] if os.path.exists(data_dir) else []
        
        if not files:
            print(f"No NVD JSON files found in {data_dir}")
            sys.exit(1)
            
        # Use the first file found
        file_path = os.path.join(data_dir, files[0])
    
    # Parse a few records and print them in detail
    parsed_records = test_nvd_parser(file_path)
    
    print("\n==== PARSED RECORDS SUMMARY ====")
    for i, record in enumerate(parsed_records):
        print(f"\nRecord {i+1}:")
        pprint(record)