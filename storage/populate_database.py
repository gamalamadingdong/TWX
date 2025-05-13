import os
import json
import sys
import time
import argparse
import xml.etree.ElementTree as ET
from pathlib import Path
import pandas as pd

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from storage.vulnerability_db import VulnerabilityDatabase
from data_processing.parse_attack import parse_attack_data
from data_processing.parse_cwe import parse_cwe_xml

def parse_args():
    """Parse command line arguments for targeted updates."""
    parser = argparse.ArgumentParser(description='Populate or update the vulnerability database')
    parser.add_argument('--all', action='store_true', help='Process all data sources')
    parser.add_argument('--cve', action='store_true', help='Process CVE data')
    parser.add_argument('--nvd', action='store_true', help='Process NVD data')
    parser.add_argument('--cwe', action='store_true', help='Process CWE data')
    parser.add_argument('--attack', action='store_true', help='Process ATT&CK data')
    parser.add_argument('--mappings', action='store_true', help='Create/update vulnerability-to-ATT&CK mappings')
    parser.add_argument('--force', action='store_true', help='Force update even if data exists')
    parser.add_argument('--export', action='store_true', help='Export classification data')
    parser.add_argument('--debug', action='store_true', help='Show debug information')
    parser.add_argument('--schema', action='store_true', help='Export database schema to SQL file')
    parser.add_argument('--schema-path', type=str, default="documentation/db_schema.sql", 
                       help='Path to save the database schema')
    args = parser.parse_args()
    
    # If no specific options are provided, default to --all
    if not (args.all or args.cve or args.nvd or args.cwe or args.attack or args.mappings or args.export):
        args.all = True
    
    return args



def ensure_directories():
    """Ensure all required directories exist."""
    required_dirs = [
        "data",
        "analysis",
        "data_collection/processed_data",
        "data_collection/raw_data/cve_data",
        "data_collection/raw_data/nvd_data",
        "data_collection/raw_data/attack_data"
    ]
    
    for directory in required_dirs:
        os.makedirs(directory, exist_ok=True)
        print(f"Ensured directory exists: {directory}")

# Add this function to your populate_database.py file

def export_db_schema(db, output_path="documentation/db_schema.sql"):
    """Export the database schema to a SQL file."""
    conn = db.connect()
    cursor = conn.cursor()
    
    # Create output directory if it doesn't exist
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    with open(output_path, 'w') as f:
        # Write header
        f.write("-- TWX Database Schema\n")
        f.write(f"-- Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        # Get all table definitions
        cursor.execute("SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';")
        tables = cursor.fetchall()
        
        f.write("-- TABLES\n")
        for name, sql in tables:
            f.write(f"{sql};\n\n")
        
        # Get all index definitions
        cursor.execute("SELECT name, sql FROM sqlite_master WHERE type='index' AND sql IS NOT NULL;")
        indexes = cursor.fetchall()
        
        if indexes:
            f.write("-- INDEXES\n")
            for name, sql in indexes:
                f.write(f"{sql};\n\n")
    
    print(f"Database schema exported to {output_path}")
    return True

def populate_cwe_data(db, cwe_xml_path, force=False):
    """Populate CWE data if it doesn't exist or if force update is requested."""
    # Check if CWE data already exists
    conn = db.connect()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM weaknesses")
    cwe_count = cursor.fetchone()[0]
    
    # Check if data is incomplete (missing names or descriptions)
    cursor.execute("SELECT COUNT(*) FROM weaknesses WHERE name = '' OR name IS NULL")
    missing_names = cursor.fetchone()[0]
    
    if cwe_count > 0 and missing_names == 0 and not force:
        print(f"CWE data already exists ({cwe_count} records). Use --force to update.")
        return False
    
    # Parse the CWE XML file
    print(f"Parsing CWE data from {cwe_xml_path}...")
    cwe_entries = parse_cwe_xml(cwe_xml_path)
    
    if not cwe_entries:
        print("Error: No CWE entries found in the XML file.")
        return False
    
    print(f"Inserting {len(cwe_entries)} CWE entries into database...")
    success_count = 0
    for entry in cwe_entries:
        try:
            if db.insert_cwe(entry):
                success_count += 1
        except Exception as e:
            print(f"Error inserting CWE {entry.get('cwe_id')}: {e}")
    
    print(f"Successfully inserted/updated {success_count} of {len(cwe_entries)} CWE entries")
    return True

def export_cwe_mappings(db, output_path="analysis/cwe_mappings.json"):
    conn = db.connect()
    df = pd.read_sql_query("SELECT * FROM weaknesses", conn)
    df.to_json(output_path, orient='records', indent=2)
    print(f"CWE mappings exported to {output_path}")

def process_attack_data(db, force=False):
    """Process and load ATT&CK data if it doesn't exist or if force update is requested."""
    # Check if ATT&CK data already exists
    conn = db.connect()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM attack_techniques")
    technique_count = cursor.fetchone()[0]
    
    if technique_count > 0 and not force:
        print(f"ATT&CK data already exists ({technique_count} techniques). Use --force to update.")
        return False
    
    # Search for the ATT&CK data file
    attack_file = find_attack_data_file()
    if not attack_file:
        print("Error: Could not find ATT&CK data file.")
        return False
    
    # Parse ATT&CK data
    print(f"Parsing ATT&CK data from {attack_file}...")
    techniques = parse_attack_data(attack_file)
    
    if not techniques:
        print("Error: No techniques found in the ATT&CK data file.")
        return False
    
    print(f"Inserting {len(techniques)} ATT&CK techniques into database...")
    inserted = 0
    
    # Insert each technique
    for technique in techniques:
        try:
            db.insert_attack_technique(technique)
            inserted += 1
        except Exception as e:
            print(f"Error inserting technique {technique.get('technique_id')}: {e}")
    
    print(f"Successfully inserted {inserted} of {len(techniques)} ATT&CK techniques")
    return True

def create_attack_mappings(db, force=False):
    """Create vulnerability-to-ATT&CK mappings if they don't exist or if force update is requested."""
    # Check if mappings already exist
    conn = db.connect()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM vulnerability_attack_mappings")
    mapping_count = cursor.fetchone()[0]
    
    if mapping_count > 0 and not force:
        print(f"Vulnerability-to-ATT&CK mappings already exist ({mapping_count} mappings). Use --force to update.")
        return False
    
    # Check if we have the prerequisites
    cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
    vuln_count = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM attack_techniques")
    technique_count = cursor.fetchone()[0]
    
    if vuln_count == 0:
        print("Error: No vulnerabilities found in the database. Mappings can't be created.")
        return False
    
    if technique_count == 0:
        print("Error: No ATT&CK techniques found in the database. Mappings can't be created.")
        return False
    
    # Delete existing mappings if force is True
    if force and mapping_count > 0:
        print(f"Deleting {mapping_count} existing mappings...")
        cursor.execute("DELETE FROM vulnerability_attack_mappings")
        conn.commit()
    
    # Create mappings
    print("Creating vulnerability-to-ATT&CK mappings...")
    try:
        from analysis.attack_mapping import create_vuln_attack_mappings
        create_vuln_attack_mappings()
        
        # Verify the results
        cursor.execute("SELECT COUNT(*) FROM vulnerability_attack_mappings")
        new_mapping_count = cursor.fetchone()[0]
        print(f"Successfully created {new_mapping_count} vulnerability-to-ATT&CK mappings")
        return True
    except Exception as e:
        print(f"Error creating vulnerability-to-ATT&CK mappings: {e}")
        return False

def find_attack_data_file():
    """Find the ATT&CK enterprise-attack.json file."""
    search_paths = [
        "data_collection/raw_data/attack_data/enterprise-attack.json",
        "raw_data/attack_data/enterprise-attack.json",
        "../data_collection/raw_data/attack_data/enterprise-attack.json",
        "./enterprise-attack.json",
        "c:/Users/samgammon/apps/TWX/data_collection/raw_data/attack_data/enterprise-attack.json"
    ]
    
    for path in search_paths:
        if os.path.exists(path):
            print(f"Found ATT&CK data at: {path}")
            return path
    
    # Search more broadly using Path objects
    try:
        # Try to find enterprise-attack.json anywhere below current directory
        for file_path in Path('.').rglob('enterprise-attack.json'):
            print(f"Found ATT&CK data at: {file_path}")
            return str(file_path)
    except Exception as e:
        print(f"Error searching for ATT&CK data: {e}")
    
    return None

def find_cwe_xml_path():
    """Find the CWE XML file path."""
    search_paths = [
        "data_collection/raw_data/cwe_data/cwec_v4.17.xml",
        "data_collection/raw_data/cwe_data/cwec_latest.xml/cwec_v4.17.xml",
        "../data_collection/raw_data/cwe_data/cwec_v4.17.xml"
    ]
    
    for path in search_paths:
        if os.path.exists(path):
            print(f"Found CWE data at: {path}")
            return path
    
    return None

def process_vulnerability_data(db, source_type="all", force=False):
    """Process vulnerability data from the specified source(s)."""
    # Check if vulnerability data already exists
    conn = db.connect()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
    vuln_count = cursor.fetchone()[0]
    
    if vuln_count > 0 and not force:
        print(f"Vulnerability data already exists ({vuln_count} vulnerabilities). Use --force to update.")
        return False
    
    # Determine which files to process
    files_to_process = []
    
    if source_type in ["all", "unified"]:
        unified_path = "data_collection/processed_data/unified_vulns.json"
        if os.path.exists(unified_path):
            files_to_process.append(("unified", unified_path))
    
    if source_type in ["all", "nvd"] and not any(f[0] == "unified" for f in files_to_process):
        nvd_path = "data_collection/processed_data/nvd_data_parsed.json"
        if os.path.exists(nvd_path):
            files_to_process.append(("nvd", nvd_path))
    
    if source_type in ["all", "cve"] and not any(f[0] == "unified" for f in files_to_process):
        cve_path = "data_collection/processed_data/cve_data_parsed.json"
        if os.path.exists(cve_path):
            files_to_process.append(("cve", cve_path))
    
    if not files_to_process:
        print(f"No {source_type} data files found. Please run data collection scripts first.")
        return False
    
    # Process each file
    for source, path in files_to_process:
        print(f"Loading {source} data from {path}...")
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            print(f"Inserting {len(data)} {source} records into database...")
            inserted = db.batch_insert_vulnerabilities(data)
            print(f"Successfully inserted {inserted} of {len(data)} {source} records into database")
        except Exception as e:
            print(f"Error processing {source} data: {e}")
    
    return True

def populate_database(args=None):
    """Process vulnerability data and populate the SQLite database based on command-line arguments."""
    if args is None:
        args = parse_args()
    
    start_time = time.time()
    
    # Ensure required directories exist
    ensure_directories()
    
    if args.debug:
        print("\n===== DEBUG INFORMATION =====")
        print(f"Current working directory: {os.getcwd()}")
        print(f"Script location: {os.path.abspath(__file__)}")
        print("\nChecking for processed data files...")
    
    # Initialize database
    print("Initializing database...")
    db = VulnerabilityDatabase()
    
    # Check database state before processing
    if args.debug:
        print("\nDatabase state before processing:")
        check_database_state(db)
    
    # Process each data type according to arguments
    processed_something = False
    
    # Process vulnerability data (CVE/NVD)
    if args.all or args.cve or args.nvd:
        source_type = "all"
        if args.cve and not args.nvd:
            source_type = "cve"
        elif args.nvd and not args.cve:
            source_type = "nvd"
        
        processed = process_vulnerability_data(db, source_type, args.force)
        processed_something = processed_something or processed
    
    # Process CWE data
    if args.all or args.cwe:
        cwe_xml_path = find_cwe_xml_path()
        if cwe_xml_path:
            processed = populate_cwe_data(db, cwe_xml_path, args.force)
            if processed:
                export_cwe_mappings(db)
            processed_something = processed_something or processed
        else:
            print("Warning: CWE data file not found")
    
    # Process ATT&CK data
    if args.all or args.attack:
        processed = process_attack_data(db, args.force)
        processed_something = processed_something or processed
    
    # Create vulnerability-to-ATT&CK mappings
    if args.all or args.mappings:
        processed = create_attack_mappings(db, args.force)
        processed_something = processed_something or processed
    
    # Export classification data
    if args.all or args.export or processed_something:
        df = export_classification_data(db)
    else:
        df = None
    
    # Check database state after processing
    if args.debug:
        print("\nDatabase state after processing:")
        check_database_state(db)
    
    if args.schema or args.debug:
        export_db_schema(db, getattr(args, 'schema_path', "documentation/db_schema.sql"))
    
    # Close database connection
    db.close()
    
    elapsed_time = time.time() - start_time
    print(f"Database population completed in {elapsed_time:.2f} seconds")
    
    return df

def check_database_state(db):
    """Check the current state of the database tables."""
    conn = db.connect()
    cursor = conn.cursor()
    
    # Get list of tables - Check if key tables exist
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = cursor.fetchall()
    
    expected_tables = [
        "vulnerabilities", 
        "weaknesses", 
        "products", 
        "vulnerability_weaknesses",
        "vulnerability_products", 
        "metrics", 
        "vuln_references",
        "attack_techniques",
        "vulnerability_attack_mappings"
    ]
    
    found_tables = [t[0] for t in tables]
    print(f"Database tables: {found_tables}")
    
    # Check for missing tables
    missing_tables = [t for t in expected_tables if t not in found_tables]
    if missing_tables:
        print(f"WARNING: Missing expected tables: {missing_tables}")
    
    # Check counts for each table
    for table in found_tables:
        try:
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            count = cursor.fetchone()[0]
            print(f"  - {table}: {count} records")
        except Exception as e:
            print(f"  - {table}: Error counting records: {e}")

def export_classification_data(db, output_path="analysis/classification_data.csv"):
    """Export classification data for analysis."""
    df = db.export_to_csv(output_path)
    print(f"Classification data exported to {output_path}")
    return df

if __name__ == "__main__":
    populate_database()