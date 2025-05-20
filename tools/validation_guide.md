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

| Type | Description | Examples |
|------|-------------|----------|
| Buffer Overflow | Occurs when software writes data outside the boundaries of allocated memory | Stack overflow, heap overflow |
| SQL Injection | Attack inserting malicious SQL code into database queries | Database code execution, data exfiltration via SQL |
| Cross-site Scripting (XSS) | Attack inserting malicious scripts into websites viewed by users | Stored XSS, Reflected XSS, DOM-based XSS |
| ... | ... | ... |

## Process
1. Use spreadsheet software to open the validation sample CSV
2. Fill in the "validated_type" column, choosing from existing types where possible
3. Record any notes or uncertainties in the "validation_notes" column
4. Save the updated CSV when complete