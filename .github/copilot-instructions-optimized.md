```instructions
# TWX Project: Cybersecurity Threat & Vulnerability Data Analysis System

## Project Context
TWX is a cybersecurity threat data analytics system designed to collect, process, analyze, and classify vulnerability data from public sources (CVE, NVD, ATT&CK). The project addresses a key challenge in cybersecurity: unbiasing threat data to reveal the true landscape of vulnerabilities rather than being skewed by multiple reports of the same issue.

## Project Goals
- Collect and normalize vulnerability data from public sources
- Build a structured database to represent relationships between vulnerabilities, weaknesses, and affected services
- Implement classification models to categorize vulnerabilities by type and severity
- Provide analytical insights on prevalence, impact, and relationships of security weaknesses
- Generate risk scores based on established frameworks (CSF, FAIR, CVSS)
- Avoid bias by properly grouping vulnerabilities to show true threat patterns

## Core Components & Architecture
1. **Data Collection**
   - CVE and NVD data acquisition (ATT&CK optional)
   - Local storage in structured formats (JSON transitioning to SQLite)

2. **Data Processing**
   - Parsers to normalize diverse data sources
   - Feature engineering for analysis and classification
   - Mapping relationships (CWE→CAPEC→ATT&CK)

3. **Storage & Knowledge Structure**
   - SQLite database with relational schema (vulnerabilities, weaknesses, products, metrics, etc.)
   - Entity relationships preserving connections between vulnerabilities and techniques

4. **Classification**
   - Vulnerability type classifier based on CWE and other features
   - Severity assessment within each vulnerability type
   - Service impact analysis showing affected systems by vulnerability type

5. **Analysis & Visualization**
   - Statistical insights on vulnerability classes, vectors, and techniques
   - Risk scoring combining prevalence and severity
   - Visualizations showing threat landscape patterns

## Project Principles
- **Accuracy & Simplicity**: Prioritize accurate classification over complexity
- **Unbiased Analysis**: Group similar vulnerabilities to show true prevalence rather than raw counts
- **Incremental Development**: Build core components first, then enhance with optional features
- **Adaptability**: Support extension with additional data sources and analysis techniques

## Development Guidelines
1. Focus on vulnerability type classification before severity scoring
2. When adding new parsers, ensure they conform to the database schema
3. Integrate visualizations that demonstrate vulnerability distributions by type and affected service
4. Prioritize data quality and proper normalization over processing speed

## Technical Implementation
- The core data model is defined in `storage/vulnerability_db.py`
- Classification logic is implemented in `models/vuln_classifier.py`
- Data processing occurs through parsers in the `data_processing/` directory
- Analysis outputs are generated in the `analysis/` directory

## Current Focus
The project is currently implementing the SQLite database integration and improving the vulnerability classification model to better identify true threat patterns rather than being skewed by repeated reports.

## Key Challenge
The primary technical challenge is properly grouping similar vulnerabilities to prevent overcounting specific vulnerability types (like multiple SQL injection reports against the same system), which would otherwise distort the true threat landscape.
```
