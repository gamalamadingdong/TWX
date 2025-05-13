# TWX Project Plan

## Project Overview
The goal of this project is to demonstrate how to collect, process, analyze, and classify cybersecurity threat and vulnerability data from publicly available sources (CVE, NVD, and optionally ATT&CK). The project will provide insights into common vulnerabilities, attack vectors, patterns, and techniques, and produce a threat/risk score based on established frameworks (CSF, FAIR).

## Objectives
- Collect and preprocess threat data from CVE and NVD (ATT&CK optional, time permitting).
- Build a structured data store or knowledge graph to represent relationships between vulnerabilities, attack vectors, and affected services.
- Implement a classification model to categorize vulnerabilities and threats.
- Provide analytical insights and statistics about vulnerabilities and threats.
- Generate a threat/risk score based on industry-standard frameworks.

---

## Phase 1: Data Collection (CVE & NVD)

### Tasks:
- Write Python scripts to fetch data from:
  - **CVE**: [https://cve.mitre.org/](https://cve.mitre.org/)
  - **Data URL**: [CVE JSON Data](https://github.com/CVEProject/cvelistV5)
  - NVD (https://nvd.nist.gov/)
  - **Data URL**: [NVD Data Feeds](https://nvd.nist.gov/vuln/data-feeds)
- Store raw data locally in JSON format.

### Tools & Libraries:
- Python (`requests`, `beautifulsoup4`, `json`)

### Deliverables:
- Data collection scripts (`fetch_cve.py`, `fetch_nvd.py`)
- Raw data files (`cve_data.json`, `nvd_data.json`)

---

## Phase 2: Data Processing and Feature Engineering

### Tasks:
- Parse and preprocess raw data into structured format.
- Extract relevant features (e.g., vulnerability class, attack vector, affected services, exploitability metrics).

### Tools & Libraries:
- Python (`pandas`, `numpy`)

### Deliverables:
- Data preprocessing scripts (`preprocess.py`, `feature_engineering.py`)
- Processed data file (`processed_data.json`)

---

## Phase 3: Knowledge Graph or Structured Data Store

### Tasks:
- Evaluate and select a suitable data storage mechanism (knowledge graph vs. relational database vs. NoSQL).
- Implement the selected storage mechanism.
- Populate the storage with processed data.

### Tools & Libraries (options):
- Knowledge Graph: Neo4j, NetworkX
- Relational Database: SQLite, PostgreSQL
- NoSQL: MongoDB

### Deliverables:
- Storage implementation scripts (`build_graph.py` or equivalent)
- Query scripts (`query_graph.py` or equivalent)

---

## Phase 4: Classification Model

### Tasks:
- Select and train a classification model to categorize vulnerabilities and threats.
- Evaluate model accuracy and refine as needed.

### Tools & Libraries:
- Python (`scikit-learn`, `xgboost`, optionally `tensorflow` or `pytorch`)

### Deliverables:
- Model training script (`train_model.py`)
- Prediction script (`predict.py`)
- Trained model artifact (`model.pkl` or equivalent)

---

## Phase 5: Analysis and Risk Scoring

### Tasks:
- Generate statistical insights (most common vulnerabilities, attack vectors, patterns, techniques, affected services).
- Implement threat/risk scoring based on CSF and FAIR frameworks, leveraging CVSS scores from NVD.

### Tools & Libraries:
- Python (`pandas`, `numpy`, custom scoring logic)

### Deliverables:
- Analysis scripts (`statistics.py`)
- Risk scoring scripts (`risk_scoring.py`)

---

## Optional Phase 6: ATT&CK Integration (Only if time permits)

### Tasks:
- Evaluate and integrate ATT&CK data to enrich analysis with adversarial tactics, techniques, and procedures (TTPs).
- **Data URL**: [ATT&CK GitHub](https://github.com/mitre/cti)

### Tools & Libraries:
- Python (`requests`, `pandas`, `NetworkX` or Neo4j)

### Deliverables:
- ATT&CK data collection and integration scripts
- Enhanced analysis scripts incorporating ATT&CK data

---

## Phase 6: Demonstration and Visualization (Optional)

### Tasks:
- Create visualizations and dashboards to demonstrate insights clearly.
- Provide interactive querying capabilities.

### Tools & Libraries:
- Python (`matplotlib`, `seaborn`, `plotly`, `streamlit`)

### Deliverables:
- Visualization scripts or notebooks (`exploratory_analysis.ipynb`)
- Interactive dashboard (optional, e.g., Streamlit app)

---

## Project Principles
- **Accuracy and Simplicity**: Prioritize clear, accurate, and understandable code and results.
- **Incremental Development**: Build and validate each component individually before integration.
- **Flexibility**: Remain open to changing architecture or tools based on practical considerations.
- **Minimal Viable Demo**: Prioritize CVE and NVD data sources first, integrate ATT&CK only if time permits.

---

## Next Steps:
Let's start with **Phase 1: Data Collection (CVE & NVD)**. Let me know when you're ready to proceed, and I'll help you write the initial scripts.