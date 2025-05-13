from typing import Dict, List, Any
import re

def extract_cvss_components(vulns: List[Dict]) -> List[Dict]:
    """Extract CVSS components from vector strings."""
    for vuln in vulns:
        cvss = vuln.get("cvss", {})
        vector = cvss.get("vector", "")
        
        # Skip if no vector
        if not vector:
            continue
        
        # Extract components based on CVSS version
        components = {}
        if vector.startswith("CVSS:3"):
            # CVSS v3 format: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
            parts = vector.split("/")
            for part in parts[1:]:  # Skip the first part (CVSS:3.x)
                if ":" in part:
                    key, value = part.split(":")
                    components[key] = value
        elif re.match(r"AV:[NALP]", vector):
            # CVSS v2 format: AV:N/AC:L/Au:N/C:P/I:P/A:P
            parts = vector.split("/")
            for part in parts:
                if ":" in part:
                    key, value = part.split(":")
                    components[key] = value
        
        vuln["cvss_components"] = components
    
    return vulns

def extract_categorical_features(vulns: List[Dict]) -> List[Dict]:
    """Extract categorical features for classification."""
    for vuln in vulns:
        features = {}
        
        # CWE category (first one if multiple)
        features["cwe"] = vuln.get("cwe", [""])[0] if vuln.get("cwe") else ""
        
        # Vendor/Product (first one if multiple)
        if vuln.get("products"):
            features["vendor"] = vuln["products"][0].get("vendor", "")
            features["product"] = vuln["products"][0].get("product", "")
        else:
            features["vendor"] = ""
            features["product"] = ""
        
        # CVSS attack vector, complexity, privileges, user interaction
        cvss_components = vuln.get("cvss_components", {})
        features["attack_vector"] = cvss_components.get("AV", "")
        features["attack_complexity"] = cvss_components.get("AC", "")
        features["privileges_required"] = cvss_components.get("PR", "")
        features["user_interaction"] = cvss_components.get("UI", "")
        
        # Known exploited status
        features["known_exploited"] = 1 if vuln.get("known_exploited", False) else 0
        
        vuln["categorical_features"] = features
    
    return vulns

def extract_numerical_features(vulns: List[Dict]) -> List[Dict]:
    """Extract numerical features for classification."""
    for vuln in vulns:
        features = {}
        
        # CVSS score
        cvss = vuln.get("cvss", {})
        features["base_score"] = cvss.get("base_score", 0)
        
        # Product count
        features["product_count"] = len(vuln.get("products", []))
        
        # Reference count
        features["reference_count"] = len(vuln.get("references", []))
        
        # Year (from ID or published date)
        vuln_id = vuln.get("id", "")
        if "CVE-" in vuln_id:
            try:
                year = int(vuln_id.split("-")[1])
                features["year"] = year
            except (IndexError, ValueError):
                features["year"] = 0
        
        vuln["numerical_features"] = features
    
    return vulns