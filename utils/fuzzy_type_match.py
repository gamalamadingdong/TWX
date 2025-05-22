"""
Fuzzy vulnerability type matching for validation and evaluation.
"""

TYPE_SYNONYMS = {
    "Buffer Overflow": {"Buffer Overflow", "Heap Overflow", "Stack Overflow", "Buffer Overrun", "Out-of-bounds Write"},
    "SQL Injection": {"SQL Injection", "SQLi", "SQL Code Injection"},
    "Cross-site Scripting (XSS)": {"Cross-site Scripting (XSS)", "XSS", "Cross Site Scripting", "Stored XSS", "Reflected XSS", "DOM-based XSS"},
    "Path Traversal": {"Path Traversal", "Directory Traversal", "File Path Traversal"},
    "Command Injection": {"Command Injection", "OS Command Injection", "Shell Injection"},
    "Deserialization": {"Deserialization", "Insecure Deserialization"},
    "Race Condition": {"Race Condition", "TOCTOU", "Time-of-check Time-of-use"},
    "Authentication Bypass": {"Authentication Bypass", "Auth Bypass", "Improper Authentication"},
    "Privilege Escalation": {"Privilege Escalation", "Elevation of Privilege", "EoP"},
    "Information Disclosure": {"Information Disclosure", "Sensitive Data Exposure", "Data Leak"},
    "Denial of Service": {"Denial of Service", "DoS", "Resource Exhaustion"},
    "Improper Input Validation": {"Improper Input Validation", "Input Validation", "Improper Validation"},
    "Cross-Site Request Forgery (CSRF)": {"Cross-Site Request Forgery (CSRF)", "CSRF"},
    "Memory Corruption": {"Memory Corruption", "Use After Free", "Dangling Pointer", "Double Free"},
    "Code Execution": {"Code Execution", "Remote Code Execution", "RCE", "Arbitrary Code Execution"},
    "Directory Listing": {"Directory Listing", "Directory Indexing"},
    "Improper Access Control": {"Improper Access Control", "Authorization Bypass", "Access Control"},
    "XML External Entity (XXE)": {"XML External Entity (XXE)", "XXE"},
    "Server-Side Request Forgery (SSRF)": {"Server-Side Request Forgery (SSRF)", "SSRF"},
    "Open Redirect": {"Open Redirect", "URL Redirection"},
    "Unrestricted File Upload": {"Unrestricted File Upload", "Arbitrary File Upload"},
    "Improper Certificate Validation": {"Improper Certificate Validation", "SSL Validation", "TLS Validation"},
    "Improper Error Handling": {"Improper Error Handling", "Information Exposure Through Error Message"},
    "Improper Authorization": {"Improper Authorization", "Authorization Bypass"},
    "Improper Resource Shutdown or Release": {"Improper Resource Shutdown or Release", "Resource Leak"},
    # Add more as needed
}

def fuzzy_type_match(predicted, validated):
    """
    Returns True if predicted and validated types are considered a fuzzy match.
    """
    if not predicted or not validated:
        return False
    predicted = predicted.strip()
    validated = validated.strip()
    # Exact match
    if predicted == validated:
        return True
    # Synonym/alias match
    for canonical, synonyms in TYPE_SYNONYMS.items():
        if predicted in synonyms and validated in synonyms:
            return True
    # Partial string match (case-insensitive)
    if predicted.lower() in validated.lower() or validated.lower() in predicted.lower():
        return True
    return False