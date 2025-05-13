"""
Parse and normalize CVE JSON data (cvelistV5 format), including ADP/KEV/vulnrichment enrichment fields.

This script is designed for the cvelistV5 schema, where:
- Metadata is under "cveMetadata"
- Main data is under "containers" -> "cna"
- Enrichment (ADP/vulnrichment) is under "containers" -> "adp" (list of dicts)

This parser extracts all relevant fields for analytics and modeling.
"""

import json
from typing import List, Dict, Any

def extract_products(cna: dict) -> List[Dict[str, str]]:
    """Enhanced product extraction with more details."""
    products = []
    for aff in cna.get("affected", []):
        vendor = aff.get("vendor", "")
        product = aff.get("product", "")
        
        # Extract platform/environment info when available
        platforms = aff.get("platforms", [])
        platform_str = ", ".join(platforms) if platforms else ""
        
        # Get detailed version info including ranges
        for version in aff.get("versions", []):
            version_info = {
                "vendor": vendor,
                "product": product,
                "version": version.get("version", ""),
                "platform": platform_str,
                "status": version.get("status", "affected"),  # 'affected' is default
                "version_affected": version.get("versionAffected", "<")
            }
            
            # Extract detailed version range info if present
            if "lessThan" in version:
                version_info["less_than"] = version["lessThan"]
            if "lessThanOrEqual" in version:
                version_info["less_than_or_equal"] = version["lessThanOrEqual"]
            if "versionEndIncluding" in version:
                version_info["version_end_including"] = version["versionEndIncluding"]
            if "versionEndExcluding" in version:
                version_info["version_end_excluding"] = version["versionEndExcluding"]
            if "versionStartIncluding" in version:
                version_info["version_start_including"] = version["versionStartIncluding"]
            if "versionStartExcluding" in version:
                version_info["version_start_excluding"] = version["versionStartExcluding"]
            
            products.append(version_info)
    
    return products

def extract_cwe(cna: dict) -> List[str]:
    """Extract CWE(s) from problemTypes."""
    cwes = []
    for pt in cna.get("problemTypes", []):
        for desc in pt.get("descriptions", []):
            cwe_id = desc.get("cweId")
            if cwe_id and cwe_id.startswith("CWE-"):
                cwes.append(cwe_id)
    return cwes

def extract_cvss(cna: dict, adp: list) -> Dict[str, Any]:
    """Enhanced CVSS extraction with detailed vector parsing."""
    # First try getting the CVSS data as before
    cvss = {}
    
    # Try ADP first (often more up-to-date)
    for adp_entry in adp:
        for metric in adp_entry.get("metrics", []):
            for key in ["cvssV3_1", "cvssV3_0", "cvssV2_0"]:
                if key in metric:
                    m = metric[key]
                    cvss = {
                        "version": m.get("version"),
                        "base_score": m.get("baseScore"),
                        "vector": m.get("vectorString"),
                        "exploitability_score": m.get("exploitabilityScore"),
                        "impact_score": m.get("impactScore"),
                        "source": "adp"
                    }
                    break
            if cvss:
                break
    
    # Fallback to CNA
    if not cvss:
        for metric in cna.get("metrics", []):
            for key in ["cvssV3_1", "cvssV3_0", "cvssV2_0"]:
                if key in metric:
                    m = metric[key]
                    cvss = {
                        "version": m.get("version"),
                        "base_score": m.get("baseScore"),
                        "vector": m.get("vectorString"),
                        "exploitability_score": m.get("exploitabilityScore"),
                        "impact_score": m.get("impactScore"),
                        "source": "cna"
                    }
                    break
            if cvss:
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
    
    return cvss

def extract_references(cna: dict) -> List[str]:
    """Extract reference URLs."""
    return [r.get("url") for r in cna.get("references", [])]

def extract_reporter(cna: dict) -> str:
    """Extract reporter/credit if present."""
    for credit in cna.get("credits", []):
        if credit.get("type") == "reporter":
            return credit.get("value", "")
    return ""

def extract_vulnrichment(adp: list) -> Dict[str, Any]:
    """Extract detailed enrichment fields from ADP."""
    result = {}
    
    # Specific CISA KEV extraction
    for adp_entry in adp:
        if "cisaKev" in adp_entry:
            kev_data = adp_entry["cisaKev"]
            result["known_exploited"] = True
            result["cisa_fields"] = {
                "kev_date_added": kev_data.get("dateAdded"),
                "kev_vendor_project": kev_data.get("vendorProject"),
                "kev_product": kev_data.get("product"),
                "kev_notes": kev_data.get("notes"),
                "kev_required_action": kev_data.get("requiredAction"),
                "kev_due_date": kev_data.get("dueDate")
            }
        
        # EPSS score (exploit prediction)
        if "epss" in adp_entry:
            result["epss_score"] = adp_entry["epss"].get("score")
            result["epss_percentile"] = adp_entry["epss"].get("percentile")
        
        # Vendor advisories
        if "vendorStatements" in adp_entry:
            result["vendor_advisories"] = adp_entry["vendorStatements"]
        
        # Exploit information
        if "exploitInfo" in adp_entry:
            result["exploit_info"] = adp_entry["exploitInfo"]
    
    # Store the raw ADP data for future reference
    result["raw_adp"] = adp
    return result

def parse_cve_record(raw: dict) -> dict:
    """Enhanced CVE parser with more comprehensive data extraction."""
    meta = raw.get("cveMetadata", {})
    cna = raw.get("containers", {}).get("cna", {})
    adp = raw.get("containers", {}).get("adp", [])

    # Description (prefer English)
    descs = cna.get("descriptions", [])
    description = next((d["value"] for d in descs if d.get("lang") == "en"), "") if descs else ""
    
    # Enhanced data extraction
    products = extract_products(cna)
    cwe = extract_cwe(cna)
    cvss = extract_cvss(cna, adp)
    references = extract_references(cna)
    reporter = extract_reporter(cna)
    vulnrichment = extract_vulnrichment(adp)
    
    # Determine if there's evidence of active exploitation
    has_exploit = any([
        vulnrichment.get("known_exploited", False),
        vulnrichment.get("exploit_info") is not None,
        vulnrichment.get("epss_score", 0) > 0.5  # High EPSS score suggests exploit likelihood
    ])
    
    # Determine if there are vendor advisories
    has_vendor_advisory = vulnrichment.get("vendor_advisories") is not None
    
    # Determine if this has a CISA advisory
    has_cisa_advisory = "cisa_fields" in vulnrichment
    
    # Analyze references for exploit information
    exploit_references = []
    if references:
        exploit_references = [ref for ref in references if is_exploit_reference(ref)]
    
    published = meta.get("datePublished")
    modified = meta.get("dateUpdated")

    return {
        "id": meta.get("cveId", raw.get("id")),
        "description": description,
        "products": products,
        "cwe": cwe,
        "capec": [],  # Placeholder for future CAPEC integration
        "attack_technique": [],  # Placeholder for future ATT&CK integration
        "cvss": cvss,
        "references": references,
        "reporter": reporter,
        "known_exploited": vulnrichment.get("known_exploited", False),
        "has_exploit": has_exploit,
        "has_cisa_advisory": has_cisa_advisory,
        "has_vendor_advisory": has_vendor_advisory,
        "exploit_references": exploit_references,
        "epss_score": vulnrichment.get("epss_score"),
        "cisa_fields": vulnrichment.get("cisa_fields", {}),
        "vulnrichment": vulnrichment,
        "other": {
            "published": published,
            "modified": modified,
        }
    }

# Add helper functions for normalized field mapping
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