# Vulnerability Classification Approach

This document explains the vulnerability classification approach used in TWX to unbias threat data and reveal the true landscape of vulnerabilities.

## The Problem: Biased Vulnerability Data

Raw vulnerability data can be misleading due to:

1. **Reporting Bias**: Some vulnerabilities are reported more frequently than others, not because they're more common but because they're easier to find or report.

2. **Multiple Reports of Same Issue**: When the same vulnerability type (e.g., SQL injection) affects a single system, it might generate dozens of individual CVE records.

3. **Severity Inconsistency**: Severity ratings can be inconsistent across different reporting sources and may not reflect the true risk in a specific context.

## Our Solution: Multi-layered Classification

TWX uses a multi-layered approach to address these biases:

### 1. Type Classification (Primary)

Instead of treating each CVE as a unique vulnerability, we group similar vulnerabilities by type based on their CWE classification. This is implemented in `map_cwe_to_vuln_type()`:

```python
def map_cwe_to_vuln_type(cwe):
    """Map CWE IDs to vulnerability type categories."""
    # This mapping groups similar vulnerabilities together
    cwe_mapping = {
        # Injection vulnerabilities
        'CWE-89': 'SQL Injection',
        'CWE-77': 'Command Injection',
        'CWE-78': 'Command Injection',
        'CWE-79': 'Cross-site Scripting (XSS)',
        # ...more mappings...
    }
    
    if cwe in cwe_mapping:
        return cwe_mapping[cwe]
    # Default fallback categories based on CWE ID ranges
    # ...
    return "Other"
```

This grouping:
- Reduces hundreds of specific CWEs to a manageable set of vulnerability types
- Prevents overcounting of specific vulnerability instances
- Makes the data more interpretable for analysis

### 2. Affected Service Analysis

For each vulnerability type, we analyze which services are most affected:

```python
def analyze_services_by_vulnerability_type(df):
    """Analyze which services are most affected by each vulnerability type."""
    results = {}
    
    # For each vulnerability type
    for vuln_type in df['vuln_type'].unique():
        # Filter to just this vulnerability type
        type_df = df[df['vuln_type'] == vuln_type]
        
        # Count occurrences of each product
        service_counts = type_df['product'].value_counts().head(10)
        
        results[vuln_type] = service_counts
        
        # Generate visualization
        # ...
    
    return results
```

This reveals:
- Which services are truly vulnerable to specific attack types
- Where to focus remediation efforts
- Real-world prevalence of vulnerabilities across different systems

### 3. Severity Distribution Analysis

Within each vulnerability type, we analyze the distribution of severity ratings:

```python
def analyze_severity_distribution(df):
    """Analyze the severity distribution across vulnerability types."""
    # Cross-tabulate vulnerability types and severity levels
    crosstab = pd.crosstab(
        df["vuln_type"], 
        df["severity"], 
        normalize="index"
    )
    
    # Visualization code
    # ...
    
    return crosstab
```

This shows:
- How severe each vulnerability type typically is
- Whether certain vulnerability types have consistent severity
- Outliers that might need special attention

### 4. Combined Risk Scoring

Finally, we calculate a combined risk score that considers both prevalence and severity:

```python
# Calculate the weighted risk score for each vulnerability type
severity_weights = {
    "Low": 1,
    "Medium": 3,
    "High": 6,
    "Critical": 10
}

risk_scores = []
for vuln_type in df["vuln_type"].unique():
    type_df = df[df["vuln_type"] == vuln_type]
    count = len(type_df)
    weighted_score = sum(type_df["severity"].map(severity_weights)) / count
    risk_scores.append({
        "vuln_type": vuln_type,
        "count": count,
        "avg_severity_weight": weighted_score,
        "risk_score": count * weighted_score  # Combines prevalence and severity
    })
```

## Benefits of This Approach

1. **Unbiased View**: By grouping and analyzing vulnerability types rather than individual instances, we avoid the bias of raw counts.

2. **Actionable Insights**: Organizations can focus on the vulnerability types that present the highest combined risk.

3. **Contextual Understanding**: By looking at affected services for each vulnerability type, we provide context that raw CVE data lacks.

4. **Prioritization**: The combined risk score helps prioritize remediation efforts based on both prevalence and severity.

## Example

Consider 100 vulnerability reports:
- 50 SQL injection reports affecting the same web application
- 10 buffer overflow reports affecting 10 different critical services
- 40 XSS reports affecting various non-critical applications

**Traditional Approach (Raw Counting)**: 
- SQL injection (50%) appears to be the dominant risk
- Buffer overflow (10%) appears to be a minor concern

**TWX Approach**:
1. **Type Classification**: Groups to SQL Injection, Buffer Overflow, and XSS
2. **Service Analysis**: Shows buffer overflow affects 10 services, SQL injection only 1
3. **Severity Analysis**: Buffer overflow has higher average severity
4. **Risk Scoring**: Buffer overflow might score higher due to critical service impact

This produces a more accurate representation of the true risk landscape, where buffer overflow might be a higher priority despite having fewer raw reports.
