"""
Parser for NVD vulnerability data in both legacy and API formats.
Supports TWX's goal of unbiasing vulnerability data through proper classification.
"""

import json
import re
import logging
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

def parse_nvd_record(nvd_item: Dict) -> Dict:
    """
    Parse an NVD vulnerability item, supporting both legacy and API formats.
    
    This function extracts comprehensive vulnerability information from NVD records
    to support TWX's goal of unbiasing vulnerability data through proper classification.
    
    Args:
        nvd_item: A single vulnerability item from NVD data feed
        
    Returns:
        Dictionary containing normalized vulnerability data
    """
    try:
        # Determine format - legacy (CVE_Items) or new API format
        is_legacy_format = "cve" in nvd_item and "CVE_data_meta" in nvd_item.get("cve", {})
        
        # Extract CVE ID based on format
        if is_legacy_format:
            cve_id = nvd_item.get("cve", {}).get("CVE_data_meta", {}).get("ID")
        else:  # New API format
            cve_id = nvd_item.get("cve", {}).get("id")
        
        # Verify we have an ID before proceeding
        if not cve_id:
            return {"parse_error": "Missing CVE ID in NVD record"}
        
        # Extract description based on format
        description = ""
        if is_legacy_format:
            desc_data = nvd_item.get("cve", {}).get("description", {}).get("description_data", [])
            for desc in desc_data:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
        else:  # New API format
            descriptions = nvd_item.get("cve", {}).get("descriptions", [])
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
        
        # Extract CWE information
        cwes = []
        if is_legacy_format:
            problem_type_data = nvd_item.get("cve", {}).get("problemtype", {}).get("problemtype_data", [])
            for problem in problem_type_data:
                for desc in problem.get("description", []):
                    if "value" in desc and desc.get("value", "").startswith("CWE-"):
                        cwes.append(desc.get("value"))
        else:  # New API format
            vuln_data = nvd_item.get("cve", {})
            if "weaknesses" in vuln_data:
                for weakness in vuln_data["weaknesses"]:
                    for desc in weakness.get("description", []):
                        if "value" in desc and desc.get("value", "").startswith("CWE-"):
                            cwes.append(desc.get("value"))
        
        # Extract CVSS data based on format
        cvss_data = {}
        if is_legacy_format:
            impact = nvd_item.get("impact", {})
            
            # Try CVSS v3 first
            if "baseMetricV3" in impact:
                cvss_v3 = impact.get("baseMetricV3", {}).get("cvssV3", {})
                if cvss_v3:
                    cvss_data = {
                        "version": "3.1" if cvss_v3.get("version") == "3.1" else "3.0",
                        "vector": cvss_v3.get("vectorString", ""),
                        "base_score": cvss_v3.get("baseScore"),
                        "base_severity": cvss_v3.get("baseSeverity", ""),
                        "attack_vector": cvss_v3.get("attackVector", ""),
                        "attack_complexity": cvss_v3.get("attackComplexity", ""),
                        "privileges_required": cvss_v3.get("privilegesRequired", ""),
                        "user_interaction": cvss_v3.get("userInteraction", ""),
                        "scope": cvss_v3.get("scope", ""),
                        "confidentiality_impact": cvss_v3.get("confidentialityImpact", ""),
                        "integrity_impact": cvss_v3.get("integrityImpact", ""),
                        "availability_impact": cvss_v3.get("availabilityImpact", ""),
                        "exploitability_score": impact.get("baseMetricV3", {}).get("exploitabilityScore"),
                        "impact_score": impact.get("baseMetricV3", {}).get("impactScore")
                    }
            
            # Fall back to CVSS v2 if needed
            elif "baseMetricV2" in impact and not cvss_data:
                cvss_v2 = impact.get("baseMetricV2", {}).get("cvssV2", {})
                if cvss_v2:
                    cvss_data = {
                        "version": "2.0",
                        "vector": cvss_v2.get("vectorString", ""),
                        "base_score": cvss_v2.get("baseScore"),
                        "base_severity": _cvss2_to_severity(cvss_v2.get("baseScore")),
                        "access_vector": cvss_v2.get("accessVector", ""),
                        "access_complexity": cvss_v2.get("accessComplexity", ""),
                        "authentication": cvss_v2.get("authentication", ""),
                        "confidentiality_impact": cvss_v2.get("confidentialityImpact", ""),
                        "integrity_impact": cvss_v2.get("integrityImpact", ""),
                        "availability_impact": cvss_v2.get("availabilityImpact", ""),
                        "exploitability_score": impact.get("baseMetricV2", {}).get("exploitabilityScore"),
                        "impact_score": impact.get("baseMetricV2", {}).get("impactScore")
                    }
        else:  # New API format
            metrics = nvd_item.get("cve", {}).get("metrics", {})
            
            # Try CVSS v3.1 first (preferred)
            if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                cvss_v31 = metrics["cvssMetricV31"][0]
                cvss_data = {
                    "version": "3.1",
                    "vector": cvss_v31.get("cvssData", {}).get("vectorString", ""),
                    "base_score": cvss_v31.get("cvssData", {}).get("baseScore"),
                    "base_severity": cvss_v31.get("cvssData", {}).get("baseSeverity", ""),
                    "attack_vector": cvss_v31.get("cvssData", {}).get("attackVector", ""),
                    "attack_complexity": cvss_v31.get("cvssData", {}).get("attackComplexity", ""),
                    "privileges_required": cvss_v31.get("cvssData", {}).get("privilegesRequired", ""),
                    "user_interaction": cvss_v31.get("cvssData", {}).get("userInteraction", ""),
                    "scope": cvss_v31.get("cvssData", {}).get("scope", ""),
                    "confidentiality_impact": cvss_v31.get("cvssData", {}).get("confidentialityImpact", ""),
                    "integrity_impact": cvss_v31.get("cvssData", {}).get("integrityImpact", ""),
                    "availability_impact": cvss_v31.get("cvssData", {}).get("availabilityImpact", ""),
                    "exploitability_score": cvss_v31.get("exploitabilityScore"),
                    "impact_score": cvss_v31.get("impactScore")
                }
            
            # Fall back to CVSS v3.0 if needed
            elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"] and not cvss_data:
                cvss_v30 = metrics["cvssMetricV30"][0]
                cvss_data = {
                    "version": "3.0",
                    "vector": cvss_v30.get("cvssData", {}).get("vectorString", ""),
                    "base_score": cvss_v30.get("cvssData", {}).get("baseScore"),
                    "base_severity": cvss_v30.get("cvssData", {}).get("baseSeverity", ""),
                    "attack_vector": cvss_v30.get("cvssData", {}).get("attackVector", ""),
                    "attack_complexity": cvss_v30.get("cvssData", {}).get("attackComplexity", ""),
                    "privileges_required": cvss_v30.get("cvssData", {}).get("privilegesRequired", ""),
                    "user_interaction": cvss_v30.get("cvssData", {}).get("userInteraction", ""),
                    "scope": cvss_v30.get("cvssData", {}).get("scope", ""),
                    "confidentiality_impact": cvss_v30.get("cvssData", {}).get("confidentialityImpact", ""),
                    "integrity_impact": cvss_v30.get("cvssData", {}).get("integrityImpact", ""),
                    "availability_impact": cvss_v30.get("cvssData", {}).get("availabilityImpact", ""),
                    "exploitability_score": cvss_v30.get("exploitabilityScore"),
                    "impact_score": cvss_v30.get("impactScore")
                }
            
            # Fall back to CVSS v2.0 if needed
            elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"] and not cvss_data:
                cvss_v2 = metrics["cvssMetricV2"][0]
                cvss_data = {
                    "version": "2.0",
                    "vector": cvss_v2.get("cvssData", {}).get("vectorString", ""),
                    "base_score": cvss_v2.get("cvssData", {}).get("baseScore"),
                    "base_severity": _cvss2_to_severity(cvss_v2.get("cvssData", {}).get("baseScore")),
                    "access_vector": cvss_v2.get("cvssData", {}).get("accessVector", ""),
                    "access_complexity": cvss_v2.get("cvssData", {}).get("accessComplexity", ""),
                    "authentication": cvss_v2.get("cvssData", {}).get("authentication", ""),
                    "confidentiality_impact": cvss_v2.get("cvssData", {}).get("confidentialityImpact", ""),
                    "integrity_impact": cvss_v2.get("cvssData", {}).get("integrityImpact", ""),
                    "availability_impact": cvss_v2.get("cvssData", {}).get("availabilityImpact", ""),
                    "exploitability_score": cvss_v2.get("exploitabilityScore"),
                    "impact_score": cvss_v2.get("impactScore")
                }
        
        # Extract references based on format
        references = []
        if is_legacy_format:
            ref_data = nvd_item.get("cve", {}).get("references", {}).get("reference_data", [])
            for ref in ref_data:
                reference = {
                    "url": ref.get("url", ""),
                    "name": ref.get("name", ref.get("url", "")),
                    "tags": ref.get("tags", [])
                }
                
                # Check if this is an exploit reference
                is_exploit = any(tag in ["exploit", "Exploit", "Attacks"] for tag in ref.get("tags", []))
                url_lower = ref.get("url", "").lower()
                if "exploit" in url_lower or "poc" in url_lower or "proof" in url_lower:
                    is_exploit = True
                    
                reference["is_exploit"] = is_exploit
                references.append(reference)
        else:  # New API format
            ref_data = nvd_item.get("cve", {}).get("references", [])
            for ref in ref_data:
                reference = {
                    "url": ref.get("url", ""),
                    "tags": ref.get("tags", [])
                }
                
                # Check if this is an exploit reference
                is_exploit = any(tag in ["exploit", "Exploit", "Attacks"] for tag in ref.get("tags", []))
                url_lower = ref.get("url", "").lower()
                if "exploit" in url_lower or "poc" in url_lower or "proof" in url_lower:
                    is_exploit = True
                    
                reference["is_exploit"] = is_exploit
                references.append(reference)
        
        # Extract affected products (CPEs) based on format
        products = []
        if is_legacy_format:
            nodes = nvd_item.get("configurations", {}).get("nodes", [])
            for node in nodes:
                if "cpe_match" in node:
                    for cpe_match in node.get("cpe_match", []):
                        cpe_uri = cpe_match.get("cpe23Uri", "")
                        if cpe_uri:
                            # Parse CPE URI format: cpe:2.3:part:vendor:product:version:...
                            parts = cpe_uri.split(':')
                            if len(parts) > 5:
                                # Extract product details from CPE URI
                                product_info = {
                                    "vendor": parts[3] or "n/a",
                                    "product": parts[4] or "n/a",
                                    "version": parts[5] or "any"
                                }
                                
                                # Add version range info if available
                                if "versionStartIncluding" in cpe_match:
                                    product_info["version_start_including"] = cpe_match["versionStartIncluding"]
                                if "versionStartExcluding" in cpe_match:
                                    product_info["version_start_excluding"] = cpe_match["versionStartExcluding"]
                                if "versionEndIncluding" in cpe_match:
                                    product_info["version_end_including"] = cpe_match["versionEndIncluding"]
                                if "versionEndExcluding" in cpe_match:
                                    product_info["version_end_excluding"] = cpe_match["versionEndExcluding"]
                                    
                                # Check if vulnerable
                                product_info["vulnerable"] = cpe_match.get("vulnerable", True)
                                
                                # Add to products list
                                products.append(product_info)
                
                # Handle nested nodes
                if "children" in node:
                    for child in node.get("children", []):
                        if "cpe_match" in child:
                            for cpe_match in child.get("cpe_match", []):
                                cpe_uri = cpe_match.get("cpe23Uri", "")
                                if cpe_uri:
                                    # Parse CPE URI
                                    parts = cpe_uri.split(':')
                                    if len(parts) > 5:
                                        # Extract product details from CPE URI
                                        product_info = {
                                            "vendor": parts[3] or "n/a",
                                            "product": parts[4] or "n/a",
                                            "version": parts[5] or "any"
                                        }
                                        
                                        # Add version range info if available
                                        if "versionStartIncluding" in cpe_match:
                                            product_info["version_start_including"] = cpe_match["versionStartIncluding"]
                                        if "versionStartExcluding" in cpe_match:
                                            product_info["version_start_excluding"] = cpe_match["versionStartExcluding"]
                                        if "versionEndIncluding" in cpe_match:
                                            product_info["version_end_including"] = cpe_match["versionEndIncluding"]
                                        if "versionEndExcluding" in cpe_match:
                                            product_info["version_end_excluding"] = cpe_match["versionEndExcluding"]
                                            
                                        # Check if vulnerable
                                        product_info["vulnerable"] = cpe_match.get("vulnerable", True)
                                        
                                        # Add to products list
                                        products.append(product_info)
        else:  # New API format
            if "configurations" in nvd_item:
                for config_node in nvd_item["configurations"]:
                    for node in config_node.get("nodes", []):
                        for cpe_match in node.get("cpeMatch", []):
                            cpe_uri = cpe_match.get("criteria", "")
                            if cpe_uri:
                                # Parse CPE URI format: cpe:2.3:part:vendor:product:version:...
                                parts = cpe_uri.split(':')
                                if len(parts) > 5:
                                    # Extract product details from CPE URI
                                    product_info = {
                                        "vendor": parts[3] or "n/a",
                                        "product": parts[4] or "n/a",
                                        "version": parts[5] or "any"
                                    }
                                    
                                    # Add version range info if available
                                    if "versionStartIncluding" in cpe_match:
                                        product_info["version_start_including"] = cpe_match["versionStartIncluding"]
                                    if "versionStartExcluding" in cpe_match:
                                        product_info["version_start_excluding"] = cpe_match["versionStartExcluding"]
                                    if "versionEndIncluding" in cpe_match:
                                        product_info["version_end_including"] = cpe_match["versionEndIncluding"]
                                    if "versionEndExcluding" in cpe_match:
                                        product_info["version_end_excluding"] = cpe_match["versionEndExcluding"]
                                        
                                    # Check if vulnerable
                                    product_info["vulnerable"] = cpe_match.get("vulnerable", True)
                                    
                                    # Add to products list
                                    products.append(product_info)
        
        # Check for KEV status
        is_kev = False
        if is_legacy_format:
            # Check legacy format for KEV info (may be in custom structures)
            pass
        else:  # New API format
            # Check for KEV information in the new API format
            if "cisaActionDue" in nvd_item or "cisaExploitAdd" in nvd_item or "cisaRequiredAction" in nvd_item:
                is_kev = True
                
        # Create cisa_kev data if needed
        cisa_kev = {}
        if is_kev:
            cisa_kev = {
                "knownExploited": True,
                "dateAdded": nvd_item.get("cisaExploitAdd", ""),
                "requiredAction": nvd_item.get("cisaRequiredAction", ""),
                "dueDate": nvd_item.get("cisaActionDue", "")
            }
        
        # Extract publish and modified dates
        published_date = ""
        modified_date = ""
        
        if is_legacy_format:
            published_date = nvd_item.get("publishedDate", "")
            modified_date = nvd_item.get("lastModifiedDate", "")
        else:  # New API format
            published_date = nvd_item.get("published", "")
            modified_date = nvd_item.get("lastModified", "")
        
        # Create normalized record
        normalized_record = {
            "id": cve_id,
            "description": description,
            "cwe": cwes,
            "products": products,
            "product_count": len(products),
            "product_names": list(set(p["product"] for p in products if p["product"] != "n/a")),
            "vendors": list(set(p["vendor"] for p in products if p["vendor"] != "n/a")),
            "cvss": cvss_data,
            "base_score": cvss_data.get("base_score", 0),
            "exploitability_score": cvss_data.get("exploitability_score", 0),
            "impact_score": cvss_data.get("impact_score", 0),
            "severity": cvss_data.get("base_severity", ""),
            "references": references,
            "reference_count": len(references),
            "exploit_references": [ref for ref in references if ref.get("is_exploit", False)],
            "has_exploit": any(ref.get("is_exploit", False) for ref in references),
            "known_exploited": is_kev,
            "published": published_date,
            "modified": modified_date,
            "published_date": published_date,
            "modified_date": modified_date,
            "vulnrichment": {
                "cisaKev": cisa_kev if is_kev else {}
            },
            "source": "nvd_legacy" if is_legacy_format else "nvd_api"
        }
        
        return normalized_record
        
    except Exception as e:
        # Return partial record with error information
        return {
            "id": nvd_item.get("cve", {}).get("CVE_data_meta", {}).get("ID", 
                  nvd_item.get("cve", {}).get("id", "Unknown")),
            "parse_error": f"Error parsing NVD record: {str(e)}",
            "error_type": str(type(e).__name__)
        }

def _cvss2_to_severity(score):
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

def process_nvd_data(data):
    """
    Process NVD data file and extract normalized records.
    
    Args:
        data: Raw NVD data (loaded from JSON)
        
    Returns:
        List of normalized NVD records
    """
    normalized_records = []
    
    # Check if this is a legacy format (CVE_Items) or newer NVD API format
    if "CVE_Items" in data:
        items = data["CVE_Items"]
        format_type = "legacy"
    elif "vulnerabilities" in data:
        items = data["vulnerabilities"]
        format_type = "new_api"
    else:
        logger.error("Unknown NVD data format")
        return []
    
    # Process each vulnerability
    for item in items:
        try:
            record = parse_nvd_record(item)
            normalized_records.append(record)
        except Exception as e:
            logger.error(f"Error processing NVD record: {str(e)}")
            continue
    
    return normalized_records

def test_parser(file_path):
    """
    Test the NVD parser with a specific file and display results.
    
    Args:
        file_path: Path to NVD JSON file
    
    Returns:
        First 5 parsed records
    """
    import json
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Determine format
        if "CVE_Items" in data:
            items = data["CVE_Items"]
            format_type = "legacy"
        elif "vulnerabilities" in data:
            items = data["vulnerabilities"]
            format_type = "new_api"
        else:
            print(f"Unknown NVD data format in {file_path}")
            return []
        
        print(f"Found {len(items)} vulnerability items in {format_type} format")
        
        # Parse first 5 items
        parsed_records = []
        for i, item in enumerate(items[:5]):
            print(f"\nProcessing item {i+1}/5")
            record = parse_nvd_record(item)
            parsed_records.append(record)
            
            # Display key info
            print(f"CVE ID: {record.get('id')}")
            print(f"Description: {record.get('description')[:100]}...")
            print(f"CWE: {record.get('cwe')}")
            print(f"Products: {len(record.get('products', []))} affected")
            
            # Show CVSS if available
            cvss = record.get('cvss', {})
            if cvss:
                print(f"CVSS v{cvss.get('version')} Score: {cvss.get('base_score')} ({cvss.get('base_severity')})")
        
        return parsed_records
        
    except Exception as e:
        print(f"Error testing NVD parser: {e}")
        import traceback
        traceback.print_exc()
        return []