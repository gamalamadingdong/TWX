# TWX: Threat & Vulnerability Intelligence Analysis

TWX is a Python-based system for collecting, processing, analyzing, and classifying cybersecurity threat and vulnerability data from public sources like CVE, NVD, and MITRE ATT&CK. It provides insights into vulnerability prevalence, attack vectors, and techniques while avoiding the bias of raw report counts.

## Project Overview

Organizations often struggle to get an accurate picture of the threat landscape because vulnerability reports can be heavily skewed (e.g., multiple reports of SQL injection against the same system make SQL injection appear disproportionately common). TWX addresses this by:

1. **Collecting data** from multiple authoritative sources
2. **Normalizing and classifying** vulnerabilities into logical groupings
3. **Analyzing prevalence and severity** within proper context
4. **Generating risk scores** based on established frameworks (CSF, FAIR)

## Features

- Data collection from CVE, NVD, and ATT&CK repositories
- SQLite database for structured storage of vulnerability data
- Classification of vulnerabilities by type (beyond just severity)
- Analysis of which services are most affected by each vulnerability class
- Risk scoring that accounts for both prevalence and severity
- Visualization of vulnerability distributions and relationships

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/TWX.git
   cd TWX
   ```

2. **Set up a virtual environment** (recommended):
   ```bash
   python -m venv .venv
   # On Windows:
   .venv\Scripts\Activate.ps1
   # On Unix/MacOS:
   # source .venv/bin/activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Data Collection

```bash
# Fetch CVE data
python data_collection/fetch_cve.py

# Fetch NVD data
python data_collection/fetch_nvd.py

# Fetch ATT&CK data (optional)
python data_collection/fetch_attack.py
```

### Data Processing and Storage

```bash
# Process all data sources
python data_processing/process_all.py

# Or process individual sources
python data_processing/parse_cve_dir.py
python data_processing/parse_nvd_dir.py
```

### Analysis and Classification

```bash
# Prepare classification data
python analysis/prepare_classification_data.py

# Run vulnerability classification and analysis
python models/vuln_classifier.py
```

### Visualization (optional)

```bash
# Run the interactive dashboard (if implemented)
python visualization/dashboard.py
```

## Project Structure

- `/data_collection`: Scripts to fetch vulnerability data from sources
- `/data_processing`: Parsers and normalizers for vulnerability data
- `/storage`: Database implementation and data access layer
- `/models`: Classification models and algorithms
- `/analysis`: Data analysis and feature engineering
- `/visualization`: Visualization tools and dashboards
- `/tests`: Unit tests for various components

## Key Technical Implementation

The project uses a hybrid approach:
- Initially processes raw JSON data into structured formats
- Stores normalized data in a SQLite database (`storage/vulnerability_db.py`)
- Classifies vulnerabilities by type using custom mapping of CWE IDs
- Analyzes which services are most affected by each vulnerability type
- Generates risk scores combining prevalence and severity metrics

## License

This project is licensed under the MIT License - see the LICENSE file for details.