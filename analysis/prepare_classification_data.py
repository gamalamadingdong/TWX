import json
import pandas as pd
import os
from datetime import datetime
import sys

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from storage.vulnerability_db import VulnerabilityDatabase

def parse_cvss_vector_fields(df, vector_col='cvss_vector'):
    """
    Parse CVSS vector strings and extract key fields (AC, UI, AV, PR, etc.) into new columns.
    """
    import re
    def extract_cvss_fields(vector):
        fields = {'ac': '', 'ui': '', 'av': '', 'pr': '', 's': '', 'c': '', 'i': '', 'a': ''}
        if not isinstance(vector, str):
            return fields
        vector = re.sub(r'^CVSS:[\d.]+/', '', vector)
        for part in vector.split('/'):
            if ':' in part:
                k, v = part.split(':', 1)
                k = k.lower()
                v = v.upper()
                if k in fields:
                    fields[k] = v
        return fields
    cvss_fields = df[vector_col].apply(extract_cvss_fields)
    cvss_df = pd.DataFrame(list(cvss_fields))
    for col in cvss_df.columns:
        df[col] = cvss_df[col]
    return df

def extract_features_from_db(db_path=None, output_path="analysis/classification_data.json", use_postgres=True):
    """
    Extract classification features directly from the database and save as JSON.
    Ensures alignment with the enhanced_classifier.py feature expectations.
    """
    # Initialize database connection based on backend
    if use_postgres:
        from storage.postgresql_db import PostgresqlVulnerabilityDatabase
        db = PostgresqlVulnerabilityDatabase()
        # Use export_to_json to get a DataFrame
        df = db.export_to_json(output_path=output_path)
    else:
        from storage.vulnerability_db import VulnerabilityDatabase
        db_file = db_path if db_path is not None else "storage/vulnerabilities.db"
        db = VulnerabilityDatabase(db_file)
        # You may need to implement a similar export for SQLite
        raise NotImplementedError("Only Postgres export is supported in this script.")

    # If export_to_json returns None, fallback to manual SQL
    if df is None or not isinstance(df, pd.DataFrame):
        query = """
        SELECT
            id as vuln_id,
            description,
            published,
            modified,
            cwe as cwe,
            cwe_name,
            cwe_category,
            vendor,
            product,
            cvss_vector,
            base_score,
            exploitability_score,
            impact_score,
            attack_vector as av,
            attack_complexity as ac,
            privileges_required as pr,
            user_interaction as ui,
            scope as s,
            confidentiality_impact as c,
            integrity_impact as i,
            availability_impact as a,
            known_exploited,
            has_cisa_advisory,
            has_vendor_advisory,
            product_count,
            reference_count,
            days_to_patch,
            exploit_maturity,
            epss_score,
            epss_percentile,
            patch_date,
            primary_cwe,
            vuln_type
        FROM vulnerabilities
        ORDER BY published DESC
        """
        conn = db.connect()
        df = pd.read_sql_query(query, conn)
        db.close()

    # Parse CVSS vector fields if not already present
    if "cvss_vector" in df.columns:
        df = parse_cvss_vector_fields(df, vector_col="cvss_vector")

    # Save as JSON for classifier
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df.to_json(output_path, orient="records", indent=2, date_format="iso")
    print(f"Classification data exported to {output_path} ({len(df)} records)")

    # Optionally, save a sample for quick inspection
    sample_path = output_path.replace(".json", "_sample.json")
    df.head(50).to_json(sample_path, orient="records", indent=2, date_format="iso")
    print(f"Sample data exported to {sample_path}")

    return df

if __name__ == "__main__":
    extract_features_from_db()