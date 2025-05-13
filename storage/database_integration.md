# Demonstration of TWX SQLite Database Integration

This document demonstrates how to use the `VulnerabilityDatabase` class from different parts of the TWX application.

## Initialization

The database should be initialized once in your application:

```python
from storage.vulnerability_db import VulnerabilityDatabase

# Initialize the database
db = VulnerabilityDatabase()
```

## Adding Vulnerability Data

You can insert vulnerability data in multiple ways:

```python
# 1. Single vulnerability insertion
vuln_data = {
    "id": "CVE-2024-12345",
    "description": "Buffer overflow in Example Software",
    "published_date": "2024-05-10",
    "cwe": ["CWE-120"],  # Buffer overflow
    "products": [
        {"vendor": "Example Inc.", "product": "Example Software", "version": "1.2.3"}
    ],
    "cvss": {
        "version": "3.1",
        "base_score": 7.8,
        "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "attack_vector": "NETWORK",
        "attack_complexity": "LOW",
        "privileges_required": "NONE",
        "user_interaction": "NONE",
        "scope": "UNCHANGED",
        "confidentiality": "HIGH",
        "integrity": "HIGH",
        "availability": "HIGH"
    },
    "references": [
        "https://example.com/advisory/12345"
    ]
}
db.insert_vulnerability(vuln_data)

# 2. Batch insertion (for multiple vulnerabilities)
vulnerabilities = [vuln_data, another_vuln_data]
db.batch_insert_vulnerabilities(vulnerabilities)
```

## Querying Vulnerabilities

```python
# 1. Get a vulnerability by ID
vulnerability = db.get_vulnerability_by_id("CVE-2024-12345")

# 2. Search vulnerabilities by criteria
vulnerabilities = db.search_vulnerabilities(
    cwe="CWE-120",  # By weakness
    product="Example Software",  # By affected product
    min_cvss=7.0,  # By minimum CVSS score
    known_exploited=True,  # Only known exploited vulnerabilities
    limit=10  # Limit results
)

# 3. Get vulnerabilities by weakness (CWE)
buffer_overflows = db.get_vulnerabilities_by_cwe("CWE-120")

# 4. Get vulnerabilities affecting a specific product
product_vulns = db.get_vulnerabilities_by_product("Example Software")

# 5. Get statistics on vulnerability types
vuln_type_stats = db.get_vulnerability_type_statistics()
```

## Preparing Data for Analysis

```python
# 1. Export data to a pandas DataFrame
df = db.export_to_dataframe()

# 2. Export data to CSV
db.export_to_csv("analysis/vulnerability_data.csv")

# 3. Get data ready for classification
classification_data = db.get_classification_data()
```

## Classification Integration

```python
# 1. In your classification script:
from storage.vulnerability_db import VulnerabilityDatabase
from models.vuln_classifier import train_classifier

# Get data from database
db = VulnerabilityDatabase()
data = db.get_classification_data()
db.close()

# Train classifier with this data
model = train_classifier(data)

# 2. To apply classification back to the database:
from storage.vulnerability_db import VulnerabilityDatabase
from models.vuln_classifier import load_classifier

# Load trained model
model = load_classifier('models/vuln_classifier.joblib')

# Get data to classify
db = VulnerabilityDatabase()
data = db.get_unclassified_vulnerabilities()

# Apply model and update database
classifications = model.predict(data)
db.update_vulnerability_classifications(data['id'], classifications)
db.close()
```

## Closing Connection

Always close the database connection when you're done:

```python
db.close()
```

## Best Practices

1. Use a single database instance per process
2. Close connections when they are no longer needed
3. Use batch insertions for better performance with large datasets
4. Export to dataframes for analysis rather than running complex queries
5. When updating the database schema, create migration scripts to handle existing data
