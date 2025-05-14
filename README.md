# This was inspired by a recent conversation. TWX is an homage to the name of a program I worked on at a previous job that was intended to be a comprehensive system for threats and vulnerabilities.  This name is a play on that program.


# TWX: Threat & Vulnerability Intelligence Analysis

TWX is a Python-based system for collecting, processing, analyzing, and classifying cybersecurity threat and vulnerability data from public sources like CVE, NVD, and MITRE ATT&CK. It provides insights into vulnerability prevalence, attack vectors, and techniques while avoiding the bias of raw report counts.

## Project Overview

Organizations often struggle to get an accurate picture of the threat landscape because vulnerability reports can be heavily skewed (e.g., multiple reports of SQL injection against the same system make SQL injection appear disproportionately common). TWX addresses this by:

1. **Collecting data** from multiple authoritative sources
2. **Normalizing and classifying** vulnerabilities into logical groupings
3. **Analyzing prevalence and severity** within proper context
4. **Generating risk scores** based on established frameworks (CSF, FAIR)
