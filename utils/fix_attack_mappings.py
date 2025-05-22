import os
import sys
import time

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from storage.vulnerability_db import VulnerabilityDatabase
from analysis.attack_mapping import create_vuln_attack_mappings, CWE_ATTACK_MAPPINGS
from data_processing.parse_attack import parse_attack_data

def fix_attack_mappings():
    """Fix the ATT&CK mappings in the database."""
    db = VulnerabilityDatabase()
    
    print("Current database state:")
    check_table_counts(db)
    
    # First, find and process ATT&CK data
    print("\nSearching for ATT&CK data file...")
    
    attack_file = None
    search_paths = [
        "data_collection/raw_data/attack_data/enterprise-attack.json",
        "raw_data/attack_data/enterprise-attack.json",
        "../data_collection/raw_data/attack_data/enterprise-attack.json",
    ]
    
    for path in search_paths:
        if os.path.exists(path):
            attack_file = path
            print(f"Found ATT&CK data at: {path}")
            break
    
    if not attack_file:
        print("Could not find ATT&CK data file. Please run fetch_attack.py first.")
        return
    
    # Process and import ATT&CK data
    print("\nProcessing ATT&CK data...")
    techniques = parse_attack_data(attack_file)
    
    if techniques:
        print(f"Inserting {len(techniques)} ATT&CK techniques into database...")
        inserted = 0
        for technique in techniques:
            if db.insert_attack_technique(technique):
                inserted += 1
        
        print(f"Successfully inserted {inserted} of {len(techniques)} ATT&CK techniques")
    else:
        print("No ATT&CK techniques found in data file.")
    
    # Create vulnerability-to-ATT&CK mappings
    print("\nCreating vulnerability-to-ATT&CK mappings...")
    create_vuln_attack_mappings()
    
    print("\nUpdated database state:")
    check_table_counts(db)
    
    # Close database connection
    db.close()
    
def populate_vulnerability_techniques():
    """
    Populate vulnerability_techniques table from vulnerability_attack_mappings.
    This bridges the gap between the mappings and the classification process.
    """
    db = VulnerabilityDatabase()
    conn = db.connect()
    cursor = conn.cursor()
    
    try:
        # Create the table if it doesn't exist
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS vulnerability_techniques (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vuln_id TEXT,
            technique_id TEXT,
            FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(id),
            FOREIGN KEY (technique_id) REFERENCES attack_techniques(technique_id)
        )
        ''')
        
        # Copy relevant data from vulnerability_attack_mappings
        cursor.execute('''
        INSERT INTO vulnerability_techniques (vuln_id, technique_id)
        SELECT DISTINCT vuln_id, technique_id FROM vulnerability_attack_mappings
        ''')
        
        count = cursor.rowcount
        conn.commit()
        print(f"Successfully populated vulnerability_techniques with {count} records")
        return True
        
    except Exception as e:
        print(f"Error populating vulnerability_techniques: {e}")
        conn.rollback()
        return False
    finally:
        conn.close()

def check_table_counts(db):
    """Check the counts of relevant tables."""
    conn = db.connect()
    cursor = conn.cursor()
    
    tables = [
        "vulnerabilities",
        "attack_techniques",
        "vulnerability_techniques",
        "vulnerability_attack_mappings"
    ]
    
    for table in tables:
        try:
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            count = cursor.fetchone()[0]
            print(f"  - {table}: {count} records")
        except Exception as e:
            print(f"  - {table}: Error counting records: {e}")

if __name__ == "__main__":
    fix_attack_mappings()