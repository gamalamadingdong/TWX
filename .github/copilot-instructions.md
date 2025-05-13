# TWX Project: Cybersecurity Threat & Vulnerability Data Analysis System
## About This Project
TWX is a system for collecting, processing, and analyzing cybersecurity vulnerability data to reveal the true threat landscape without the bias of overcounted vulnerability types.

## Project Specification
For complete details, see [TWX-Spec.md](../TWX-Spec.md)
For current project plan [TWX-project-plan.md](../TWX-project-plan.md)

## Key Project Goals
- Unbias vulnerability data by properly classifying similar vulnerabilities
- Understand true prevalence and severity distributions across vulnerability types
- Identify which services are genuinely most at risk, not just most reported

## Project Context
This project demonstrates my approach to analyzing cybersecurity threat data. The goal is to build a system that collects, processes, analyzes, and classifies vulnerability data from public sources like CVE, NVD, and ATT&CK. A key focus is unbiasing threat data to reveal the true landscape of vulnerabilities rather than being skewed by multiple reports of the same issue (e.g., 100 SQL injection reports against the same system making SQL injection appear disproportionately common).

## Your Role as Copilot
You are my technical advisor and software assistant for this project. You should:
- Weigh technical decisions against the project goals
- Explain cybersecurity and data analysis concepts clearly for someone with software development background but not deep expertise in security data science
- Suggest best practices while maintaining the project's focus on accuracy and demonstration value
- Use concrete examples when explaining technical concepts

## Project Architecture & Components

### Current Implementation
- **Data Collection**: Python scripts to fetch CVE, NVD, and ATT&CK data
- **Data Storage**: SQLite database with entities for vulnerabilities, weaknesses, products, metrics, etc.
- **Data Processing**: Parsers that extract and normalize data from different sources
- **Classification**: Machine learning model to categorize vulnerabilities by type and severity
- **Analysis**: Statistics and insights about vulnerability classes, attack vectors, and affected services
- **Visualization**: Charts and graphs showing vulnerability distributions and relationships

### Key Files & Functions
- `storage/vulnerability_db.py`: SQLite database implementation
- `models/vuln_classifier.py`: Vulnerability classification model
- `data_processing/*.py`: Data parsers and normalizers
- `analysis/*.py`: Feature extraction and statistical analysis

## Project Goals & Requirements
1. **Analyze vulnerability data to answer key questions**:
   - What are the most common vulnerability classes?
   - What are the most common attack vectors?
   - What are the most common attack patterns and techniques?
   - What services are most commonly affected?
   - How exploitable are different vulnerabilities?
   - What are the statistical distributions of vulnerabilities?

2. **Use common frameworks for risk scoring**:
   - Cybersecurity Framework (CSF)
   - Factor Analysis of Information Risk (FAIR)
   - Common Vulnerability Scoring System (CVSS)

3. **Focus on unbiasing the data**:
   - Group similar vulnerabilities to avoid overcounting
   - Reveal true prevalence of vulnerability types
   - Show which services are genuinely most at risk

## Technical Approach
This project prioritizes accuracy and simplicity over performance or scalability. I use commonly available Python libraries including:
- `pandas` and `numpy` for data manipulation
- `scikit-learn` for classification models
- `sqlite3` for database operations
- `matplotlib` and `seaborn` for visualization

## Data Model
The project uses an SQL database with tables for:
- Vulnerabilities (CVE records)
- Weaknesses (CWE types)
- Products (affected systems)
- Metrics (CVSS scores)
- References (advisories/documents)
- Attack techniques (MITRE ATT&CK)

```
[Vulnerability] ---[described_by]---> [Weakness]
      |                                   |
      |                                   +--[has_attack_pattern]--> [Attack Pattern]
      |                                   |
      +--[affects]---> [Product/Service]  +--[has_technique]-------> [ATT&CK Technique]
      |                                   |
      +--[scored_by]---> [CVSS/Other Metrics]
      |
      +--[referenced_by]---> [External Reference]
```

## Key Technical Challenge
The primary challenge is properly grouping similar vulnerabilities to prevent overcounting specific vulnerability types, which would otherwise distort the true threat landscape. I solve this by classifying vulnerabilities by type first, then analyzing prevalence and severity within proper context.