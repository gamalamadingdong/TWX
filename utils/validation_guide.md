# TWX Vulnerability Classification Validation Guide

## Purpose
This document provides guidance for manually validating vulnerability classifications to create a gold standard dataset for model evaluation.

## Instructions

### For each vulnerability:
1. Read the CVE description carefully
2. Review the CWE mapping and any referenced information
3. Determine the correct vulnerability type based on the information provided
4. If the original classification is correct, copy it to the "validated_type" field
5. If incorrect, enter the correct classification in "validated_type"
6. Add any notes or reasoning in the "validation_notes" field

### Classification Guidelines

When determining vulnerability types, consider:

1. **Root Cause**: What vulnerability allows the exploit?
2. **Attack Vector**: How is the vulnerability exploited?
3. **Impact**: What can an attacker achieve?

### Vulnerability Type Definitions

| Type | Description | Examples/Synonyms |
|------|-------------|-------------------|
| Buffer Overflow | Occurs when software writes data outside the boundaries of allocated memory | Stack Overflow, Heap Overflow, Buffer Overrun, Out-of-bounds Write |
| SQL Injection | Attack inserting malicious SQL code into database queries | SQLi, SQL Code Injection |
| Cross-site Scripting (XSS) | Attack inserting malicious scripts into websites viewed by users | XSS, Cross Site Scripting, Stored XSS, Reflected XSS, DOM-based XSS |
| Path Traversal | Attack that manipulates file paths to access files outside intended directories | Directory Traversal, File Path Traversal |
| Command Injection | Attack that injects OS commands into a program | OS Command Injection, Shell Injection |
| Deserialization | Exploiting insecure deserialization of data | Insecure Deserialization |
| Race Condition | Exploiting timing issues in code execution | TOCTOU, Time-of-check Time-of-use |
| Authentication Bypass | Circumventing authentication mechanisms | Auth Bypass, Improper Authentication |
| Privilege Escalation | Gaining higher privileges than intended | Elevation of Privilege, EoP |
| Information Disclosure | Unintended exposure of sensitive data | Sensitive Data Exposure, Data Leak |
| Denial of Service | Causing a service to become unavailable | DoS, Resource Exhaustion |
| Improper Input Validation | Failure to properly validate input | Input Validation, Improper Validation |
| Cross-Site Request Forgery (CSRF) | Forcing a user to execute unwanted actions | CSRF |
| Memory Corruption | Exploiting memory management errors | Use After Free, Dangling Pointer, Double Free |
| Code Execution | Ability to execute arbitrary code | Remote Code Execution, RCE, Arbitrary Code Execution |
| Directory Listing | Unintended exposure of directory contents | Directory Indexing |
| Improper Access Control | Inadequate enforcement of access restrictions | Authorization Bypass, Access Control |
| XML External Entity (XXE) | Exploiting XML parsers to access external entities | XXE |
| Server-Side Request Forgery (SSRF) | Causing the server to make unintended requests | SSRF |
| Open Redirect | Redirecting users to untrusted sites | URL Redirection |
| Unrestricted File Upload | Uploading files without proper validation | Arbitrary File Upload |
| Improper Certificate Validation | Failing to properly validate SSL/TLS certificates | SSL Validation, TLS Validation |
| Improper Error Handling | Leaking information via error messages | Information Exposure Through Error Message |
| Improper Authorization | Inadequate authorization checks | Authorization Bypass |
| Improper Resource Shutdown or Release | Failing to release resources properly | Resource Leak |

*This list is not exhaustive. Use the closest matching type and document any uncertainty in the notes.*

## Process
1. Use spreadsheet software to open the validation sample CSV
2. Fill in the "validated_type" column, choosing from existing types or synonyms where possible
3. Record any notes or uncertainties in the "validation_notes" column
4. Save the updated CSV when complete

## Fuzzy Matching for Evaluation

When evaluating model predictions, types that are synonyms or close matches (see above) will be considered correct. This reflects the real-world ambiguity in vulnerability classification.