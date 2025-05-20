"""
Test version of CVE parser that processes just a few records and prints detailed debug information
to diagnose the AttributeError issues.
"""

import json
import os
import sys
from pprint import pprint

def load_cve_json(file_path):
    """Load CVE JSON data with error handling."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            print(f"Successfully loaded JSON from {file_path}")
            print(f"Top level keys: {list(data.keys())}")
            return data
    except Exception as e:
        print(f"Error loading CVE file {file_path}: {str(e)}")
        return None

def parse_single_cve(cve_json):
    """Parse a single CVE record with detailed logging."""
    try:
        # Check data structure
        print("Examining CVE structure...")
        
        # Try to extract CVE ID
        cve_id = None
        if "cveMetadata" in cve_json:
            cve_id = cve_json["cveMetadata"].get("cveId")
            print(f"Found CVE ID in cveMetadata: {cve_id}")
        elif "CVE_data_meta" in cve_json:
            cve_id = cve_json["CVE_data_meta"].get("ID")
            print(f"Found CVE ID in CVE_data_meta: {cve_id}")
        else:
            print("Could not find CVE ID in expected locations")
            # Try to find anything that looks like a CVE ID
            for key, value in cve_json.items():
                if isinstance(value, str) and value.startswith("CVE-"):
                    cve_id = value
                    print(f"Found potential CVE ID in field {key}: {cve_id}")
                    break
        
        if not cve_id:
            print("No CVE ID found, cannot parse record")
            return None
            
        # Find the container with main CVE data (cvelistV5 format vs. legacy)
        cna = None
        description = None
        
        if "containers" in cve_json and "cna" in cve_json["containers"]:
            # cvelistV5 format
            print("Using cvelistV5 format parser")
            cna = cve_json["containers"]["cna"]
            
            # Extract description
            for desc in cna.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
                    
            print(f"Description: {description[:100]}..." if description else "No description found")
            
            # Extract CWEs
            cwes = []
            problem_types = cna.get("problemTypes", [])
            print(f"Found {len(problem_types)} problem types")
            
            for problem in problem_types:
                descriptions = problem.get("descriptions", [])
                for desc in descriptions:
                    if "cweId" in desc:
                        cwe_id = desc["cweId"]
                        if cwe_id and cwe_id not in cwes:
                            if not cwe_id.startswith("CWE-"):
                                cwe_id = f"CWE-{cwe_id}"
                            cwes.append(cwe_id)
                            
            print(f"CWEs found: {cwes}")
            
            # Extract affected products
            products = []
            for aff in cna.get("affected", []):
                vendor = aff.get("vendor", "")
                product = aff.get("product", "")
                
                for version in aff.get("versions", []):
                    version_info = {
                        "vendor": vendor,
                        "product": product,
                        "version": version.get("version", ""),
                    }
                    products.append(version_info)
            
            print(f"Found {len(products)} affected product versions")
            if products:
                print(f"First product: {products[0]}")
            
            # Extract CVSS data
            cvss_data = {}
            metrics_entries = cna.get("metrics", [])
            print(f"Found {len(metrics_entries)} metrics entries")
            
            for entry in metrics_entries:
                if entry.get("format") == "CVSS" and entry.get("version") == "3.1":
                    cvss31 = entry.get("cvssV3_1", {})
                    if cvss31:
                        cvss_data = {
                            "version": "3.1",
                            "vector": cvss31.get("vectorString", ""),
                            "base_score": cvss31.get("baseScore"),
                            "base_severity": cvss31.get("baseSeverity", ""),
                        }
                        break
            
            print(f"CVSS data: {cvss_data}")
            
        else:
            # Legacy format or unknown
            print("CVE data not found in expected container structure")
            print("Available top-level keys:", list(cve_json.keys()))
            
            # Try to extract basic info anyway
            if "description" in cve_json:
                description_data = cve_json.get("description", {}).get("description_data", [])
                for desc in description_data:
                    if desc.get("lang") == "en":
                        description = desc.get("value", "")
                        break
            
            print(f"Description: {description[:100]}..." if description else "No description found")
        
        # Create normalized record with available data
        normalized_record = {
            "id": cve_id,
            "description": description if description else "",
            "cwe": cwes if 'cwes' in locals() else [],
            "products": products if 'products' in locals() else [],
            "cvss": cvss_data if 'cvss_data' in locals() else {},
            "format": "cvelistV5" if "containers" in cve_json else "legacy"
        }
        
        print("Successfully parsed CVE")
        return normalized_record
        
    except Exception as e:
        print(f"Error parsing CVE: {str(e)}")
        import traceback
        traceback.print_exc()
        if 'cve_id' in locals() and cve_id:
            return {"id": cve_id, "parse_error": str(e)}
        else:
            return {"id": "unknown", "parse_error": str(e)}

def test_cve_parser(file_path):
    """Test CVE parser on a single CVE file."""
    print(f"Testing CVE parser on {file_path}")
    data = load_cve_json(file_path)
    if not data:
        return None
        
    parsed = parse_single_cve(data)
    return parsed

def test_cve_directory(directory_path, limit=5):
    """Test CVE parser on multiple files in a directory."""
    print(f"Testing CVE parser on directory {directory_path}")
    
    if not os.path.exists(directory_path):
        print(f"Directory {directory_path} not found")
        return []
    
    # Find all JSON files in the directory (non-recursive)
    json_files = [os.path.join(directory_path, f) for f in os.listdir(directory_path) 
                  if f.endswith('.json') and os.path.isfile(os.path.join(directory_path, f))]
    
    if not json_files:
        print(f"No JSON files found in {directory_path}")
        return []
    
    print(f"Found {len(json_files)} JSON files, will process up to {limit}")
    
    parsed_records = []
    for i, file_path in enumerate(json_files[:limit]):
        print(f"\n--- Processing file {i+1}/{min(limit, len(json_files))}: {os.path.basename(file_path)} ---")
        try:
            data = load_cve_json(file_path)
            if data:
                parsed = parse_single_cve(data)
                if parsed:
                    parsed_records.append(parsed)
        except Exception as e:
            print(f"Error processing file {file_path}: {str(e)}")
    
    print(f"\nSuccessfully parsed {len(parsed_records)} records")
    return parsed_records

if __name__ == "__main__":
    # Check if file or directory path is provided as argument
    if len(sys.argv) > 1:
        path = sys.argv[1]
        if os.path.isdir(path):
            parsed_records = test_cve_directory(path)
        else:
            parsed = test_cve_parser(path)
            parsed_records = [parsed] if parsed else []
    else:
        # Try to find CVE files to parse
        year_dirs = ["data_collection/raw_data/cve_data/cves/2023", 
                    "data_collection/raw_data/cve_data/cves/2024"]
        
        for year_dir in year_dirs:
            if os.path.exists(year_dir):
                # Find a subdirectory with CVEs
                subdirs = [os.path.join(year_dir, d) for d in os.listdir(year_dir) 
                          if os.path.isdir(os.path.join(year_dir, d))]
                
                if subdirs:
                    # Use the first subdirectory
                    test_dir = subdirs[0]
                    print(f"Testing with directory: {test_dir}")
                    parsed_records = test_cve_directory(test_dir)
                    break
        else:
            print("No suitable CVE directories found")
            sys.exit(1)
    
    print("\n==== PARSED RECORDS SUMMARY ====")
    for i, record in enumerate(parsed_records):
        print(f"\nRecord {i+1}:")
        pprint(record)