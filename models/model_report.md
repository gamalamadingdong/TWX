# Vulnerability Classification Report

## Model Performance Metrics
| Metric | Value |
|--------|-------|
| **Accuracy** | 0.44 |
| **Macro Average** | Precision: 0.37, Recall: 0.55, F1-score: 0.36 |
| **Weighted Average** | Precision: 0.70, Recall: 0.44, F1-score: 0.48 |

## Classification Results by Vulnerability Type

| Vulnerability Type | Precision | Recall | F1-Score | Support |
|-------------------|-----------|--------|----------|---------|
| Access Control Issues | 0.73 | 0.40 | 0.52 | 4,750 |
| Authentication Issues | 0.66 | 0.35 | 0.46 | 2,074 |
| Broken/Risky Crypto | 0.35 | 0.43 | 0.39 | 399 |
| Buffer Overflow | 0.73 | 0.33 | 0.46 | 13,923 |
| Certificate Validation | 0.13 | 0.62 | 0.22 | 465 |
| Cleartext Transmission | 0.16 | 0.49 | 0.24 | 299 |
| Code Injection | 0.41 | 0.44 | 0.42 | 1,157 |
| Command Injection | 0.52 | 0.53 | 0.52 | 3,454 |
| Cross-Site Request Forgery (CSRF) | 0.35 | 0.83 | 0.49 | 2,096 |
| Cross-site Scripting (XSS) | 0.85 | 0.68 | 0.75 | 13,640 |
| Deserialization of Untrusted Data | 0.30 | 0.51 | 0.38 | 1,018 |
| Double Free | 0.17 | 0.63 | 0.26 | 702 |
| Expression Language Injection | 0.06 | 0.70 | 0.11 | 47 |
| Hardcoded Credentials | 0.05 | 0.46 | 0.09 | 480 |
| Heap-based Buffer Overflow | 0.24 | 0.60 | 0.34 | 2,539 |
| Improper Input Validation | 0.55 | 0.38 | 0.45 | 4,428 |
| Inadequate Encryption Strength | 0.19 | 0.61 | 0.29 | 165 |
| Information Disclosure | 0.34 | 0.43 | 0.38 | 2,553 |
| Injection | 0.26 | 0.54 | 0.35 | 1,134 |
| Link Following | 0.06 | 0.74 | 0.12 | 734 |
| Memory Leak | 0.15 | 0.80 | 0.25 | 1,185 |
| NULL Pointer Dereference | 0.49 | 0.23 | 0.32 | 3,832 |
| Open Redirect | 0.09 | 0.68 | 0.15 | 461 |
| Other | 0.99 | 0.31 | 0.47 | 32,454 |
| Out-of-bounds Read | 0.50 | 0.62 | 0.55 | 6,556 |
| Out-of-bounds Write | 0.49 | 0.38 | 0.43 | 9,722 |
| Path Traversal | 0.58 | 0.30 | 0.39 | 2,800 |
| Privilege Escalation | 0.38 | 0.60 | 0.47 | 2,275 |
| Race Condition | 0.27 | 0.88 | 0.41 | 1,615 |
| Resource Allocation | 0.17 | 0.51 | 0.26 | 835 |
| Resource Exhaustion | 0.26 | 0.64 | 0.36 | 2,705 |
| SQL Injection | 0.21 | 0.67 | 0.32 | 3,329 |
| SSRF | 0.77 | 0.69 | 0.73 | 1,773 |
| Security Bypass | 0.47 | 0.56 | 0.51 | 1,047 |
| Session Fixation | 0.07 | 0.66 | 0.13 | 117 |
| Stack-based Buffer Overflow | 0.49 | 0.66 | 0.57 | 2,288 |
| Unknown | 0.98 | 0.34 | 0.51 | 27,327 |
| Unrestricted File Upload | 0.15 | 0.28 | 0.20 | 1,063 |
| Use After Free | 0.52 | 0.41 | 0.46 | 5,413 |
| Weak Credentials | 0.31 | 0.45 | 0.37 | 527 |
| Weak Random | 0.43 | 0.78 | 0.55 | 322 |
| Weak Salt | 0.00 | 1.00 | 0.00 | 1 |
| XML Injection | 0.07 | 0.77 | 0.13 | 44 |
| XXE | 0.11 | 0.43 | 0.18 | 358 |

## Top 5 Vulnerability Types by Risk Score

After excluding 'Unknown' and 'Other' vulnerability types (298,905 records):

| Vulnerability Type | Count | Avg Severity Weight | Risk Score |
|-------------------|-------|---------------------|------------|
| Buffer Overflow | 69,618 | 5.61 | 390,551.67 |
| Out-of-bounds Write | 48,609 | 5.84 | 284,024.51 |
| Cross-site Scripting (XSS) | 68,199 | 3.39 | 230,926.82 |
| Out-of-bounds Read | 32,779 | 4.99 | 163,589.75 |
| Use After Free | 27,065 | 5.67 | 153,512.36 |