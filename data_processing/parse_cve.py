"""
Parser for CVE data in both cvelistV5 and legacy formats.
Supports TWX's goal of unbiasing vulnerability data through proper classification.
"""

import json
import re
import os
import logging
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

def extract_description(cna: dict) -> str:
    """Extract the English language description from a CVE record."""
    # Look for descriptions in cvelistV5 format
    if "descriptions" in cna:
        for desc in cna["descriptions"]:
            if desc.get("lang") == "en":
                return desc.get("value", "")
    
    # No English description found
    return ""

def extract_dates(cve_json: dict) -> dict:
    """Extract published and modified dates from a CVE record."""
    dates = {}
    
    # Get from cveMetadata (cvelistV5 format)
    if "cveMetadata" in cve_json:
        metadata = cve_json["cveMetadata"]
        if "datePublished" in metadata:
            dates["published"] = metadata["datePublished"]
        if "dateUpdated" in metadata:
            dates["modified"] = metadata["dateUpdated"]
    
    return dates

def extract_reporter(cve_json: dict) -> str:
    """Extract the CVE reporter information."""
    reporter = ""
    
    # Get from cveMetadata (cvelistV5 format)
    if "cveMetadata" in cve_json:
        metadata = cve_json["cveMetadata"]
        if "assignerShortName" in metadata:
            reporter = metadata["assignerShortName"]
    
    return reporter

def extract_cwes(cna: dict) -> List[str]:
    """Extract CWE IDs from the problemTypes field in cvelistV5 format."""
    cwes = []
    
    # Navigate through problemTypes structure to find CWEs (note the plural)
    problem_types = cna.get("problemTypes", [])
    
    for problem in problem_types:
        descriptions = problem.get("descriptions", [])
        
        for desc in descriptions:
            # Check for cweId format used in cvelistV5
            if "cweId" in desc:
                cwe_id = desc["cweId"]
                # Standardize CWE format (ensure it has CWE- prefix)
                if cwe_id:
                    if not cwe_id.startswith("CWE-"):
                        cwe_id = f"CWE-{cwe_id}"
                    if cwe_id not in cwes:
                        cwes.append(cwe_id)
            # Also check for older 'type': 'CWE' format
            elif desc.get("type") == "CWE":
                # Try to extract CWE ID from description text or value
                for field in ["value", "description"]:
                    if field in desc and desc[field]:
                        # Try to extract CWE-XXX pattern
                        cwe_match = re.search(r'CWE-(\d+)', desc[field])
                        if cwe_match:
                            cwe_id = f"CWE-{cwe_match.group(1)}"
                            if cwe_id not in cwes:
                                cwes.append(cwe_id)
                        # If no pattern match but field has a numeric value, prefix with CWE-
                        elif desc[field].isdigit():
                            cwe_id = f"CWE-{desc[field]}"
                            if cwe_id not in cwes:
                                cwes.append(cwe_id)
    
    # If still no CWEs found, try legacy format for backward compatibility
    if not cwes and "problemType" in cna:  # Note: singular form as fallback
        for desc in cna["problemType"].get("descriptions", []):
            if desc.get("type") == "CWE" and "value" in desc:
                cwe_value = desc["value"]
                if cwe_value.startswith("CWE-"):
                    cwes.append(cwe_value)
                elif cwe_value.isdigit():
                    cwes.append(f"CWE-{cwe_value}")
    
    # Ensure all CWE IDs are in standard format (CWE-XXX)
    normalized_cwes = []
    for cwe in cwes:
        if cwe.startswith("CWE-"):
            normalized_cwes.append(cwe)
        elif cwe.isdigit():
            normalized_cwes.append(f"CWE-{cwe}")
        # Handle potential "CWE" prefix without hyphen
        elif cwe.startswith("CWE") and cwe[3:].isdigit():
            normalized_cwes.append(f"CWE-{cwe[3:]}")
            
    return normalized_cwes

def extract_products(cna: dict) -> List[Dict[str, Any]]:
    """Extract affected products from a CVE record."""
    products = []
    
    # Process each affected entry
    for aff in cna.get("affected", []):
        # Get vendor and product info
        vendor = aff.get("vendor", "n/a")
        product = aff.get("product", "n/a")
        
        # Get platform information if available
        platforms = aff.get("platforms", [])
        platform_str = ", ".join(platforms) if platforms else ""
        
        # Get additional product metadata
        product_metadata = {}
        if "collectionURL" in aff:
            product_metadata["collection_url"] = aff["collectionURL"]
            
        if "defaultStatus" in aff:
            product_metadata["default_status"] = aff["defaultStatus"]
        
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
            
            # Include product metadata in each version entry
            if product_metadata:
                version_info["product_metadata"] = product_metadata
            
            # Extract detailed version range info
            for range_field in ["lessThan", "lessThanOrEqual", "versionEndIncluding", 
                              "versionEndExcluding", "versionStartIncluding", "versionStartExcluding"]:
                if range_field in version:
                    snake_case = re.sub(r'([A-Z])', r'_\1', range_field).lower()
                    version_info[snake_case] = version[range_field]
                    
            # Extract version change info if available
            if "changes" in version:
                version_info["changes"] = version["changes"]
                
            products.append(version_info)
    
    return products

def extract_references(cna: dict) -> List[Dict[str, Any]]:
    """Extract references from a CVE record."""
    references = []
    
    # Process each reference
    for ref in cna.get("references", []):
        reference = {
            "url": ref.get("url", ""),
            "name": ref.get("name", ""),
            "tags": ref.get("tags", [])
        }
        
        # Check if this is an exploit reference
        is_exploit = False
        exploit_tags = ["exploit", "poc", "exploit-db", "metasploit"]
        
        # Check URL for exploit indicators
        url = reference["url"].lower()
        if any(tag in url for tag in ["exploit", "poc", "proof", "cve-"]):
            is_exploit = True
        
        # Check tags for exploit indicators
        if any(tag.lower() in exploit_tags for tag in reference.get("tags", [])):
            is_exploit = True
            
        reference["is_exploit"] = is_exploit
        references.append(reference)
    
    return references

def extract_cvss(cna: dict) -> Dict[str, Any]:
    """Extract CVSS metrics from a CVE record."""
    cvss_data = {}
    
    # Process metrics entries
    for entry in cna.get("metrics", []):
        # Look for CVSS v3.1 first (preferred)
        if entry.get("format") == "CVSS" and entry.get("version") == "3.1":
            cvss31 = entry.get("cvssV3_1", {})
            if cvss31:
                cvss_data = {
                    "version": "3.1",
                    "vector": cvss31.get("vectorString", ""),
                    "base_score": cvss31.get("baseScore"),
                    "base_severity": cvss31.get("baseSeverity", ""),
                    "attack_vector": cvss31.get("attackVector", ""),
                    "attack_complexity": cvss31.get("attackComplexity", ""),
                    "privileges_required": cvss31.get("privilegesRequired", ""),
                    "user_interaction": cvss31.get("userInteraction", ""),
                    "scope": cvss31.get("scope", ""),
                    "confidentiality_impact": cvss31.get("confidentialityImpact", ""),
                    "integrity_impact": cvss31.get("integrityImpact", ""),
                    "availability_impact": cvss31.get("availabilityImpact", "")
                }
                
                # Add exploitability and impact scores if available
                if "exploitabilityScore" in cvss31:
                    cvss_data["exploitability_score"] = cvss31["exploitabilityScore"]
                else:
                    # Calculate from vector components if not provided
                    cvss_data["exploitability_score"] = 0  # Replace with calculation if needed
                
                if "impactScore" in cvss31:
                    cvss_data["impact_score"] = cvss31["impactScore"]
                else:
                    # Calculate from vector components if not provided
                    cvss_data["impact_score"] = 0  # Replace with calculation if needed
                
                # Found CVSS 3.1, so return this data
                return cvss_data
                
        # Fall back to CVSS v3.0 if no v3.1
        elif entry.get("format") == "CVSS" and entry.get("version") == "3.0":
            cvss30 = entry.get("cvssV3", {})
            if cvss30:
                cvss_data = {
                    "version": "3.0",
                    "vector": cvss30.get("vectorString", ""),
                    "base_score": cvss30.get("baseScore"),
                    "base_severity": cvss30.get("baseSeverity", ""),
                    "attack_vector": cvss30.get("attackVector", ""),
                    "attack_complexity": cvss30.get("attackComplexity", ""),
                    "privileges_required": cvss30.get("privilegesRequired", ""),
                    "user_interaction": cvss30.get("userInteraction", ""),
                    "scope": cvss30.get("scope", ""),
                    "confidentiality_impact": cvss30.get("confidentialityImpact", ""),
                    "integrity_impact": cvss30.get("integrityImpact", ""),
                    "availability_impact": cvss30.get("availabilityImpact", "")
                }
                
                # Add exploitability and impact scores
                if "exploitabilityScore" in cvss30:
                    cvss_data["exploitability_score"] = cvss30["exploitabilityScore"]
                else:
                    cvss_data["exploitability_score"] = 0
                
                if "impactScore" in cvss30:
                    cvss_data["impact_score"] = cvss30["impactScore"]
                else:
                    cvss_data["impact_score"] = 0
                
                # Return CVSS 3.0 data if found
                return cvss_data
                
        # Fall back to CVSS v2
        elif entry.get("format") == "CVSS" and entry.get("version") == "2.0":
            cvss2 = entry.get("cvssV2", {})
            if cvss2:
                cvss_data = {
                    "version": "2.0",
                    "vector": cvss2.get("vectorString", ""),
                    "base_score": cvss2.get("baseScore"),
                    "base_severity": _cvss2_severity(cvss2.get("baseScore")),
                    "access_vector": cvss2.get("accessVector", ""),
                    "access_complexity": cvss2.get("accessComplexity", ""),
                    "authentication": cvss2.get("authentication", ""),
                    "confidentiality_impact": cvss2.get("confidentialityImpact", ""),
                    "integrity_impact": cvss2.get("integrityImpact", ""),
                    "availability_impact": cvss2.get("availabilityImpact", "")
                }
                
                # Add exploitability and impact scores
                if "exploitabilityScore" in cvss2:
                    cvss_data["exploitability_score"] = cvss2["exploitabilityScore"]
                else:
                    cvss_data["exploitability_score"] = 0
                
                if "impactScore" in cvss2:
                    cvss_data["impact_score"] = cvss2["impactScore"]
                else:
                    cvss_data["impact_score"] = 0
                
                # Return CVSS 2.0 data if found
                return cvss_data
    
    # Return empty dict if no CVSS data found
    return cvss_data

def _cvss2_severity(score):
    """Convert CVSS v2 score to severity rating."""
    if score is None:
        return ""
    try:
        score = float(score)
        if score < 4.0:
            return "LOW"
        elif score < 7.0:
            return "MEDIUM"
        elif score < 10.0:
            return "HIGH"
        else:
            return "CRITICAL"
    except (ValueError, TypeError):
        return ""

def extract_vulnrichment(cve_json: Dict) -> Dict:
    """Extract vulnerability enrichment data like CISA KEV, EPSS, etc."""
    enrichment = {}
    
    # Check for vulnrichment container in cvelistV5 format
    containers = cve_json.get("containers", {})
    adp_list = containers.get("adp", [])
    
    # Process ADP entries which may contain KEV data
    for adp in adp_list:
        if "title" in adp and "CVE Program Container" in adp.get("title", ""):
            # This is likely a KEV record
            if "cisaKev" in adp:
                # Process KEV data
                kev = adp["cisaKev"]
                enrichment["cisaKev"] = kev
                
                # Extract key KEV fields for easier access
                if kev.get("knownExploited"):
                    enrichment["known_exploited"] = kev.get("knownExploited")
                    
                if "knownRansomwareCampaignUse" in kev:
                    enrichment["known_ransomware"] = kev.get("knownRansomwareCampaignUse")
                    
                if "dateAdded" in kev:
                    enrichment["kev_date_added"] = kev["dateAdded"]
                    
                if "requiredAction" in kev:
                    enrichment["kev_required_action"] = kev["requiredAction"]
                    
                if "dueDate" in kev:
                    enrichment["kev_due_date"] = kev["dueDate"]
    
    # Check for vulnrichment container (might be in a different location in some records)
    if "vulnrichment" in containers:
        vulnrichment = containers["vulnrichment"]
        
        # Process CISA KEV data if available
        if "cisaKev" in vulnrichment:
            kev = vulnrichment["cisaKev"]
            enrichment["cisaKev"] = kev
            
            # Extract key KEV fields for easier access
            if kev.get("knownExploited"):
                enrichment["known_exploited"] = kev.get("knownExploited")
                
            if "knownRansomwareCampaignUse" in kev:
                enrichment["known_ransomware"] = kev.get("knownRansomwareCampaignUse")
                
            if "dateAdded" in kev:
                enrichment["kev_date_added"] = kev["dateAdded"]
                
            if "requiredAction" in kev:
                enrichment["kev_required_action"] = kev["requiredAction"]
                
            if "dueDate" in kev:
                enrichment["kev_due_date"] = kev["dueDate"]
        
        # Process EPSS data if available
        if "epss" in vulnrichment:
            epss = vulnrichment["epss"]
            if "score" in epss:
                try:
                    enrichment["epss_score"] = float(epss["score"])
                except (ValueError, TypeError):
                    pass
                    
            if "percentile" in epss:
                try:
                    enrichment["epss_percentile"] = float(epss["percentile"])
                except (ValueError, TypeError):
                    pass
    
    return enrichment

def has_exploit_references(references: List[Dict]) -> bool:
    """Check if any references indicate exploit availability."""
    for ref in references:
        if ref.get("is_exploit", False):
            return True
    return False

def infer_cwe_from_description(description: str) -> List[str]:
    """
    Infer likely CWE IDs when explicit CWE information is not provided.
    Used as a fallback for CVEs without CWE mappings.
    """
    if not description:
        return []
    
    description = description.lower()
    inferred_cwes = []
    
    # Map keywords to CWE IDs - ordered by specificity
    keyword_cwe_map = {
        # SQL Injection patterns
        'sql injection': 'CWE-89',
        'sqli ': 'CWE-89',
        'sql command': 'CWE-89',
        
        # XSS patterns
        'cross-site scripting': 'CWE-79',
        'cross site scripting': 'CWE-79',
        'xss': 'CWE-79',
        
        # Command Injection
        'command injection': 'CWE-78',
        'os command': 'CWE-78',
        'shell injection': 'CWE-78',
        
        # Path Traversal
        'path traversal': 'CWE-22',
        'directory traversal': 'CWE-22',
        'file inclusion': 'CWE-98',
        
        # Memory Safety
        'buffer overflow': 'CWE-120',
        'stack overflow': 'CWE-121',
        'heap overflow': 'CWE-122',
        'use after free': 'CWE-416',
        'null pointer': 'CWE-476',
        
        # Authentication
        'authentication bypass': 'CWE-287',
        'hardcoded password': 'CWE-798',
        'weak password': 'CWE-521',
        
        # Information Disclosure
        'information disclosure': 'CWE-200',
        'sensitive information': 'CWE-200',
        
        # Access Control
        'improper authorization': 'CWE-285',
        'improper access control': 'CWE-284',
        'privilege escalation': 'CWE-269',
    }
    
    for keyword, cwe_id in keyword_cwe_map.items():
        if keyword in description and cwe_id not in inferred_cwes:
            inferred_cwes.append(cwe_id)
    
    return inferred_cwes

def parse_cve_record(cve_json: Dict) -> Dict:
    """
    Parse a CVE record in cvelistV5 format, extracting all relevant fields.
    
    This function supports TWX's goal of unbiasing vulnerability data through proper
    classification by extracting and normalizing all pertinent information.
    """
    try:
        # Extract CVE ID from metadata
        metadata = cve_json.get("cveMetadata", {})
        cve_id = metadata.get("cveId")
        
        if not cve_id:
            return {"parse_error": "Missing CVE ID in metadata"}
        
        # Get CNA container which has most of the data
        containers = cve_json.get("containers", {})
        cna = containers.get("cna", {})
        
        if not cna:
            return {"id": cve_id, "parse_error": "Missing CNA container"}
        
        # Extract all relevant fields
        description = extract_description(cna)
        products = extract_products(cna)
        references = extract_references(cna)
        
        # Extract CWEs, falling back to inference if needed
        cwes = extract_cwes(cna)
        if not cwes:
            # If no explicit CWEs found, try to infer from description
            inferred_cwes = infer_cwe_from_description(description)
            if inferred_cwes:
                cwes = inferred_cwes
                # Mark these as inferred
                inferred = True
            else:
                # If still no CWEs, use a generic "Unclassified Weakness"
                cwes = ["CWE-1035"]  # "Vulnerable Code" - a good default
                inferred = True
        else:
            inferred = False
            
        cvss_data = extract_cvss(cna)
        dates = extract_dates(cve_json)
        reporter = extract_reporter(cve_json)
        
        # Extract enrichment data like KEV, EPSS
        vulnrichment = extract_vulnrichment(cve_json)
        
        # Determine if the vulnerability has exploit references
        exploit_available = has_exploit_references(references)
        
        # Check for certain keywords in references that might indicate advisory types
        has_cisa = any("cisa.gov" in ref.get("url", "") for ref in references)
        has_vendor = any("vendor" in ref.get("tags", []) for ref in references)
        
        # Build normalized record with all extracted data
        normalized_record = {
            "id": cve_id,
            "description": description,
            "products": products,
            "product_count": len(products),
            "product_names": list(set(p["product"] for p in products if p["product"] != "n/a")),
            "vendors": list(set(p["vendor"] for p in products if p["vendor"] != "n/a")),
            "cwe": cwes,
            "cwe_inferred": inferred,
            "capec": [],  # To be filled by mapper
            "attack_technique": [],  # To be filled by mapper
            "cvss": cvss_data,
            "base_score": cvss_data.get("base_score", 0),
            "exploitability_score": cvss_data.get("exploitability_score", 0),
            "impact_score": cvss_data.get("impact_score", 0),
            "severity": cvss_data.get("base_severity", ""),
            "references": references,
            "reference_count": len(references),
            "reference_details": references,  # Full reference details
            "exploit_references": [ref for ref in references if ref.get("is_exploit", False)],
            "vulnrichment": vulnrichment,
            "reporter": reporter,
            "known_exploited": vulnrichment.get("cisaKev", {}).get("knownExploited", False),
            "has_cisa_advisory": has_cisa,
            "has_vendor_advisory": has_vendor,
            "exploit_available": exploit_available,
            "has_exploit": exploit_available,
            "exploit_maturity": 3 if vulnrichment.get("cisaKev", {}).get("knownExploited", False) else (
                2 if exploit_available else 1
            ),
            "published": dates.get("published", ""),
            "modified": dates.get("modified", ""),
            "published_date": dates.get("published", ""),
            "modified_date": dates.get("modified", ""),
            "epss_score": vulnrichment.get("epss_score"),
            "epss_percentile": vulnrichment.get("epss_percentile"),
            "cisa_fields": {
                "kev_date_added": vulnrichment.get("kev_date_added"),
                "kev_due_date": vulnrichment.get("kev_due_date"),
                "kev_required_action": vulnrichment.get("kev_required_action"),
                "known_ransomware": vulnrichment.get("known_ransomware", False)
            },
            "other": {
                "source": "cve_v5_format"
            }
        }
        
        return normalized_record
    
    except Exception as e:
        # Return partial record with error information if parsing fails
        return {
            "id": cve_json.get("cveMetadata", {}).get("cveId", "Unknown"),
            "parse_error": f"Error parsing CVE record: {str(e)}",
            "error_type": str(type(e).__name__)
        }

def test_parser(file_path):
    """
    Test the parser with a specific CVE file.
    
    Args:
        file_path: Path to CVE JSON file
        
    Returns:
        Parsed CVE record
    """
    import json
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            cve_json = json.load(f)
        
        parsed = parse_cve_record(cve_json)
        
        # Display key info
        print(f"CVE ID: {parsed.get('id')}")
        print(f"Description: {parsed.get('description')[:100]}...")
        print(f"CWE: {parsed.get('cwe')}")
        if parsed.get('cwe_inferred'):
            print("Note: CWEs were inferred from description")
        print(f"Products: {len(parsed.get('products', []))} affected")
        for product in parsed.get('products', [])[:3]:  # Show first 3
            print(f"  - {product.get('vendor')}/{product.get('product')}")
        
        # Show CVSS if available
        cvss = parsed.get('cvss', {})
        if cvss:
            print(f"CVSS v{cvss.get('version')} Score: {cvss.get('base_score')}" + 
                 f" ({cvss.get('base_severity')})")
            
        return parsed
    except Exception as e:
        print(f"Error testing parser: {e}")
        return None