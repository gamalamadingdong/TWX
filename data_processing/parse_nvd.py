"""
Parse and normalize NVD JSON data, including KEV and vulnrichment enrichment fields.

This script loads raw NVD JSON, extracts and flattens all relevant fields (including enrichment),
and outputs a unified, analysis-ready JSON file. This supports unbiased grouping, classification,
and analytics as described in the project plan.

Why this matters:
- NVD data includes additional enrichment (CVSS, CPE, references) not always present in CVE.
- Ensures all vulnerability data is consistent and ready for downstream analytics and modeling.
"""

import json
from typing import List, Dict, Any

def load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def extract_cwe(problemtype: dict) -> List[str]:
    """Extract CWE(s) from the problemType field."""
    cwes = []
    if not problemtype:
        return cwes
    for desc in problemtype.get("problemtype_data", []):
        for item in desc.get("description", []):
            val = item.get("value")
            if val and val.startswith("CWE-"):
                cwes.append(val)
    return cwes

def extract_cvss(nvd_item: dict) -> Dict[str, Any]:
    """Enhanced CVSS extraction with detailed vector parsing."""
    impact = nvd_item.get("impact", {})
    cvss = {}
    
    # Try V3 first, then fall back to V2
    for version_key, cvss_key in [("baseMetricV3", "cvssV3"), ("baseMetricV2", "cvssV2")]:
        metric = impact.get(version_key)
        if metric:
            cvss_data = metric.get(cvss_key, {})
            cvss = {
                "version": cvss_data.get("version"),
                "base_score": cvss_data.get("baseScore"),
                "vector": cvss_data.get("vectorString"),
                "exploitability_score": metric.get("exploitabilityScore"),
                "impact_score": metric.get("impactScore"),
                "source": "nvd"
            }
            break
    
    # Parse the vector string into individual components
    if cvss and "vector" in cvss and cvss["vector"]:
        vector_parts = {}
        vector_str = cvss["vector"]
        
        # Handle the CVSS:3.x/AV:N/AC:L/... format
        if "/" in vector_str:
            parts = vector_str.split("/")
            for part in parts:
                if ":" in part:
                    key, value = part.split(":", 1)
                    vector_parts[key] = value
        
        # Extract specific vector components
        cvss["attack_vector"] = vector_parts.get("AV")
        cvss["attack_complexity"] = vector_parts.get("AC")
        cvss["privileges_required"] = vector_parts.get("PR")
        cvss["user_interaction"] = vector_parts.get("UI")
        cvss["scope"] = vector_parts.get("S")
        cvss["confidentiality"] = vector_parts.get("C")
        cvss["integrity"] = vector_parts.get("I")
        cvss["availability"] = vector_parts.get("A")
        
        # Add normalized fields for classification
        cvss["av"] = map_attack_vector(vector_parts.get("AV"))
        cvss["ac"] = map_attack_complexity(vector_parts.get("AC"))
        cvss["pr"] = map_privileges_required(vector_parts.get("PR"))
        cvss["ui"] = map_user_interaction(vector_parts.get("UI"))
        cvss["s"] = map_scope(vector_parts.get("S"))
        cvss["c"] = map_cia_impact(vector_parts.get("C"))
        cvss["i"] = map_cia_impact(vector_parts.get("I"))
        cvss["a"] = map_cia_impact(vector_parts.get("A"))
    
    return cvss

def extract_products(configurations: dict) -> List[Dict[str, str]]:
    """Enhanced product extraction with version ranges and platform details."""
    products = []
    for node in configurations.get("nodes", []):
        for cpe in node.get("cpe_match", []):
            cpe23 = cpe.get("cpe23Uri", "")
            parts = cpe23.split(":")
            
            if len(parts) >= 5:
                product_info = {
                    "vendor": parts[3],
                    "product": parts[4],
                    "version": parts[5] if len(parts) > 5 else "",
                    "status": "affected" if cpe.get("vulnerable", True) else "not_affected"
                }
                
                # Extract platform details if present
                if len(parts) > 10 and parts[10]:
                    product_info["platform"] = parts[10]
                
                # Extract version range information
                if "versionStartIncluding" in cpe:
                    product_info["version_start_including"] = cpe["versionStartIncluding"]
                if "versionStartExcluding" in cpe:
                    product_info["version_start_excluding"] = cpe["versionStartExcluding"]
                if "versionEndIncluding" in cpe:
                    product_info["version_end_including"] = cpe["versionEndIncluding"]
                if "versionEndExcluding" in cpe:
                    product_info["version_end_excluding"] = cpe["versionEndExcluding"]
                
                products.append(product_info)
    
    return products

def extract_references(cve: dict) -> List[Dict[str, str]]:
    """Enhanced reference extraction with type classification."""
    references = []
    
    for ref in cve.get("references", {}).get("reference_data", []):
        url = ref.get("url", "")
        ref_type = "unknown"
        
        # Classify reference types based on content
        if is_exploit_reference(url):
            ref_type = "exploit"
        elif is_patch_reference(url):
            ref_type = "patch"
        elif is_vendor_reference(url):
            ref_type = "vendor"
        
        references.append({
            "url": url,
            "source": ref.get("name", ""),
            "type": ref_type,
            "tags": ref.get("tags", [])
        })
    
    return references

def extract_vulnrichment(cve: dict) -> Dict[str, Any]:
    """Enhanced extraction of vulnrichment and KEV fields."""
    v = cve.get("vulnrichment", {})
    cisa_kev = v.get("cisaKev", {})
    
    result = {
        "known_exploited": cisa_kev.get("known_exploited", False),
        "cisa_fields": {
            "kev_date_added": cisa_kev.get("dateAdded"),
            "kev_vendor_project": cisa_kev.get("vendorProject"),
            "kev_product": cisa_kev.get("product"),
            "kev_notes": cisa_kev.get("notes"),
            "kev_required_action": cisa_kev.get("requiredAction"),
            "kev_due_date": cisa_kev.get("dueDate")
        }
    }
    
    # Extract EPSS score if present
    if "epss" in v:
        result["epss_score"] = v["epss"].get("score")
        result["epss_percentile"] = v["epss"].get("percentile")
    
    # Store the raw vulnrichment data for future reference
    result["vulnrichment"] = v
    
    return result

def parse_nvd_record(item: dict) -> dict:
    """Enhanced parser for NVD records with more comprehensive data extraction."""
    cve = item.get("cve", {})
    meta = cve.get("CVE_data_meta", {})
    
    # Description (prefer English)
    descs = cve.get("description", {}).get("description_data", [])
    description = next((d["value"] for d in descs if d.get("lang") == "en"), "") if descs else ""
    
    # Enhanced data extraction
    products = extract_products(item.get("configurations", {}))
    cwe = extract_cwe(cve.get("problemtype", {}))
    cvss = extract_cvss(item)
    references_data = extract_references(cve)
    reference_urls = [ref["url"] for ref in references_data]
    
    enrichment = extract_vulnrichment(cve)
    
    # Determine if there's evidence of active exploitation
    exploit_references = [ref["url"] for ref in references_data if ref["type"] == "exploit"]
    has_exploit = any([
        enrichment.get("known_exploited", False),
        len(exploit_references) > 0,
        enrichment.get("epss_score", 0) > 0.5  # High EPSS score suggests exploit likelihood
    ])
    
    # Determine if there are vendor advisories
    has_vendor_advisory = any(ref["type"] == "vendor" for ref in references_data)
    
    # Determine if this has a CISA advisory
    has_cisa_advisory = enrichment.get("known_exploited", False)
    
    return {
        "id": meta.get("ID", item.get("id")),
        "description": description,
        "products": products,
        "cwe": cwe,
        "capec": [],  # Placeholder for future CAPEC integration
        "attack_technique": [],  # Placeholder for future ATT&CK integration
        "cvss": cvss,
        "references": reference_urls,
        "references_data": references_data,
        "reporter": "",  # Not commonly available in NVD
        "known_exploited": enrichment.get("known_exploited", False),
        "has_exploit": has_exploit,
        "has_cisa_advisory": has_cisa_advisory,
        "has_vendor_advisory": has_vendor_advisory,
        "exploit_references": exploit_references,
        "epss_score": enrichment.get("epss_score"),
        "cisa_fields": enrichment.get("cisa_fields", {}),
        "vulnrichment": enrichment.get("vulnrichment", {}),
        "other": {
            "published": item.get("publishedDate"),
            "modified": item.get("lastModifiedDate"),
        }
    }

# Helper functions for normalized field mapping
def map_attack_vector(av):
    """Map CVSS attack vector to normalized value."""
    if not av:
        return "Unknown"
    mapping = {
        "N": "Network",
        "A": "Adjacent", 
        "L": "Local",
        "P": "Physical"
    }
    return mapping.get(av, av)

def map_attack_complexity(ac):
    """Map CVSS attack complexity to normalized value."""
    if not ac:
        return "Unknown"
    mapping = {
        "L": "Low",
        "H": "High"
    }
    return mapping.get(ac, ac)

def map_privileges_required(pr):
    """Map CVSS privileges required to normalized value."""
    if not pr:
        return "Unknown"
    mapping = {
        "N": "None",
        "L": "Low",
        "H": "High"
    }
    return mapping.get(pr, pr)

def map_user_interaction(ui):
    """Map CVSS user interaction to normalized value."""
    if not ui:
        return "Unknown"
    mapping = {
        "N": "None",
        "R": "Required"
    }
    return mapping.get(ui, ui)

def map_scope(s):
    """Map CVSS scope to normalized value."""
    if not s:
        return "Unknown"
    mapping = {
        "U": "Unchanged",
        "C": "Changed"
    }
    return mapping.get(s, s)

def map_cia_impact(impact):
    """Map CVSS CIA impact to normalized value."""
    if not impact:
        return "Unknown"
    mapping = {
        "N": "None",
        "L": "Low",
        "H": "High"
    }
    return mapping.get(impact, impact)

def is_exploit_reference(url):
    """Check if a reference URL suggests exploit information."""
    if not isinstance(url, str):
        return False
        
    exploit_indicators = [
        "exploit-db.com",
        "exploit",
        "poc",
        "proof-of-concept",
        "metasploit",
        "github.com",  # Many exploits are published on GitHub
        "vulmon.com/exploitdetails",
        "packetstormsecurity.com"
    ]
    
    lower_url = url.lower()
    return any(indicator in lower_url for indicator in exploit_indicators)

def is_patch_reference(url):
    """Check if a reference URL suggests patch/fix information."""
    if not isinstance(url, str):
        return False
        
    patch_indicators = [
        "patch",
        "update",
        "fix",
        "advisory",
        "security bulletin",
        "release notes"
    ]
    
    lower_url = url.lower()
    return any(indicator in lower_url for indicator in patch_indicators)

def is_vendor_reference(url):
    """Check if a reference URL is from a vendor."""
    if not isinstance(url, str):
        return False
        
    vendor_domains = [
        "microsoft.com",
        "apple.com",
        "oracle.com",
        "cisco.com",
        "ibm.com",
        "vmware.com",
        "adobe.com",
        "redhat.com",
        "debian.org",
        "canonical.com",
        "ubuntu.com",
        "sap.com",
        "siemens.com"
    ]
    
    lower_url = url.lower()
    return any(domain in lower_url for domain in vendor_domains)

def parse_all_nvd(input_path: str, output_path: str):
    """Parse all NVD records in a file and write unified output."""
    data = load_json(input_path)
    records = data.get("CVE_Items", [])
    parsed = [parse_nvd_record(r) for r in records]
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(parsed, f, indent=2)
    print(f"Parsed {len(parsed)} NVD records and saved to {output_path}")

if __name__ == "__main__":
    # Example usage: parse NVD JSON to unified format
    parse_all_nvd("data_collection/raw_data/nvd_data.json", "data_collection/processed_data/nvd_data_parsed.json")