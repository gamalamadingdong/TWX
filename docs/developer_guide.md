# TWX Developer Guide

This guide provides an overview of the TWX project architecture, components, and how they interact. It's intended for developers who want to understand and contribute to the project.

## Architecture Overview

TWX is organized into several distinct components, each handling specific responsibilities:

1. **Data Collection**: Fetches raw data from CVE, NVD, and ATT&CK sources
2. **Data Processing**: Normalizes and transforms raw data into a structured format
3. **Storage**: Manages a SQLite database for storing and retrieving vulnerability data
4. **Classification**: Categorizes vulnerabilities by type and severity using ML models
5. **Analysis**: Extracts insights and patterns from the vulnerability dataset
6. **Visualization**: Displays vulnerability data in a meaningful way

```
[Data Collection] → [Data Processing] → [Storage] ↔ [Classification]
                                           ↓
                                      [Analysis] → [Visualization]
```

## Component Details

### Data Collection

Located in the `data_collection/` directory:

- `fetch_cve.py`: Downloads CVE data from MITRE's CVE List
- `fetch_nvd.py`: Downloads NVD data from NIST's data feeds
- `fetch_attack.py`: Downloads ATT&CK framework data (optional)

Data is stored in `data_collection/raw_data/` with subdirectories for each source.

### Data Processing

Located in the `data_processing/` directory:

- `parse_cve.py` & `parse_cve_dir.py`: Parse CVE records
- `parse_nvd.py` & `parse_nvd_dir.py`: Parse NVD records
- `process_all.py`: Orchestrates processing of all data sources

This component also includes:
- Normalizers (`normalizers/`): Extract and normalize features
- Mappers (`mappers/`): Connect data across different sources (e.g., CWE to CAPEC to ATT&CK)

### Storage

Located in the `storage/` directory:

- `vulnerability_db.py`: SQLite database implementation
- Schema includes tables for vulnerabilities, weaknesses, products, metrics, etc.

### Classification

Located in the `models/` directory:

- `vuln_classifier.py`: Machine learning model for vulnerability classification
- Uses scikit-learn to categorize vulnerabilities by type and severity
- Important functions include `map_cwe_to_vuln_type()` which groups similar vulnerabilities together

### Analysis

Located in the `analysis/` directory:

- `prepare_classification_data.py`: Prepares data for the classifier
- `explore_data.py`: General data exploration and statistics
- Functions in the classification module also provide analytical capabilities:
  - `analyze_services_by_vulnerability_type()`
  - `analyze_severity_distribution()`
  - `calculate_risk_scores()`

### Visualization

Located in the `visualization/` directory:

- Currently uses matplotlib and seaborn for visualization
- Can be extended with interactive dashboards (e.g., using Streamlit)

## Data Flow

1. Raw vulnerability data is collected from sources (CVE, NVD)
2. Data is parsed into a normalized format by parsers
3. Normalized data is stored in the SQLite database
4. Classification models categorize vulnerabilities
5. Analysis functions extract insights from the data
6. Visualizations present the results

## Development Workflow

1. **Setup Environment**:
   ```bash
   python -m venv .venv
   .venv\Scripts\Activate.ps1  # On Windows
   pip install -r requirements.txt
   ```

2. **Data Collection**:
   ```bash
   python data_collection/fetch_cve.py
   python data_collection/fetch_nvd.py
   ```

3. **Data Processing**:
   ```bash
   python data_processing/process_all.py
   ```

4. **Analysis & Classification**:
   ```bash
   python models/vuln_classifier.py
   ```

## Key Design Decisions

1. **SQLite Database**: Chosen for simplicity and portability, while still providing relational capabilities
2. **Vulnerability Type Classification**: Groups similar vulnerabilities (e.g., all SQL injection types) to prevent overcounting
3. **Feature Engineering**: Extracts CVSS components and other metrics for vulnerability analysis
4. **CWE Mapping**: Maps CWE IDs to higher-level vulnerability types to simplify analysis

## Adding New Features

### New Data Source
1. Create fetch script in `data_collection/`
2. Create parser in `data_processing/`
3. Integrate with `process_all.py`
4. Update database schema if necessary

### New Analysis
1. Add analysis function to appropriate module
2. Ensure it works with the database schema
3. Add visualization if relevant

### New Classification Feature
1. Update `prepare_data()` in `vuln_classifier.py`
2. Adjust classifier parameters if needed
3. Test with cross-validation

## Testing

Currently, tests are located in the `tests/` directory:

- Unit tests for parsers, database operations, and classifiers
- Integration tests for the overall workflow

## Future Enhancements

1. **Interactive Dashboard**: Implement a Streamlit-based dashboard for visualization
2. **Advanced Classification**: Use more sophisticated ML techniques for vulnerability categorization
3. **Temporal Analysis**: Analyze vulnerability trends over time
4. **Network Effects**: Analyze relationships between vulnerabilities affecting the same services
