-- TWX Database Schema
-- Generated: 2025-05-13 12:38:54

-- TABLES
CREATE TABLE vulnerabilities (
            id TEXT PRIMARY KEY,
            description TEXT,
            published_date TEXT,
            modified_date TEXT,
            known_exploited INTEGER DEFAULT 0,
            has_exploit INTEGER DEFAULT 0,
            has_cisa_advisory INTEGER DEFAULT 0,
            has_vendor_advisory INTEGER DEFAULT 0,
            epss_score REAL,
            epss_percentile REAL,
            kev_date_added TEXT,
            kev_vendor_project TEXT,
            kev_product TEXT,
            kev_notes TEXT,
            kev_required_action TEXT,
            kev_due_date TEXT
        );

CREATE TABLE weaknesses (
            cwe_id TEXT PRIMARY KEY,
            name TEXT,
            description TEXT
        , category TEXT, extended_description TEXT, mitigations TEXT);

CREATE TABLE products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vendor TEXT,
            product TEXT,
            version TEXT,
            platform TEXT,
            version_start_including TEXT,
            version_start_excluding TEXT,
            version_end_including TEXT,
            version_end_excluding TEXT,
            UNIQUE(vendor, product, version)
        );

CREATE TABLE vulnerability_weaknesses (
            vuln_id TEXT,
            cwe_id TEXT,
            PRIMARY KEY (vuln_id, cwe_id),
            FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(id),
            FOREIGN KEY (cwe_id) REFERENCES weaknesses(cwe_id)
        );

CREATE TABLE vulnerability_products (
            vuln_id TEXT,
            product_id INTEGER,
            PRIMARY KEY (vuln_id, product_id),
            FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(id),
            FOREIGN KEY (product_id) REFERENCES products(id)
        );

CREATE TABLE metrics (
            vuln_id TEXT PRIMARY KEY,
            cvss_version TEXT,
            base_score REAL,
            vector TEXT,
            attack_vector TEXT,
            attack_complexity TEXT,
            privileges_required TEXT,
            user_interaction TEXT,
            scope TEXT,
            confidentiality TEXT,
            integrity TEXT,
            availability TEXT,
            exploitability_score REAL,
            impact_score REAL,
            FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(id)
        );

CREATE TABLE vuln_references (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vuln_id TEXT,
            url TEXT,
            reference_type TEXT,
            FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(id)
        );

CREATE TABLE attack_techniques (
            technique_id TEXT PRIMARY KEY,
            name TEXT,
            tactic TEXT,
            description TEXT
        );

CREATE TABLE vulnerability_techniques (
            vuln_id TEXT,
            technique_id TEXT,
            PRIMARY KEY (vuln_id, technique_id),
            FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(id),
            FOREIGN KEY (technique_id) REFERENCES attack_techniques(technique_id)
        );

CREATE TABLE vulnerability_attack_mappings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vuln_id TEXT,
            technique_id TEXT,
            mapping_type TEXT,
            confidence REAL,
            FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(id),
            FOREIGN KEY (technique_id) REFERENCES attack_techniques(technique_id)
        );

-- INDEXES
CREATE INDEX idx_vuln_weaknesses_vuln_id ON vulnerability_weaknesses (vuln_id);

CREATE INDEX idx_vuln_weaknesses_cwe_id ON vulnerability_weaknesses (cwe_id);

CREATE INDEX idx_vuln_products_vuln_id ON vulnerability_products (vuln_id);

CREATE INDEX idx_vuln_products_product_id ON vulnerability_products (product_id);

CREATE INDEX idx_vuln_references_vuln_id ON vuln_references (vuln_id);

