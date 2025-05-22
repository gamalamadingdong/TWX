import os
import sys
import logging
import json
import argparse
from tqdm import tqdm

# Set up proper imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from storage.vulnerability_db import VulnerabilityDatabase
from data_processing.mappers.cwe_capec_mapper import load_cwe_capec_mapping, generate_cwe_capec_mapping
from data_processing.cwe_vulnerability_types import get_vulnerability_type

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def parse_args():
    parser = argparse.ArgumentParser(description='Create vulnerability mappings')
    parser.add_argument('--postgres', action='store_true', help='Use PostgreSQL instead of SQLite')
    parser.add_argument('--force', action='store_true', help='Force recreation of all mappings')
    parser.add_argument('--cwe', action='store_true', help='Create only CWE mappings')
    parser.add_argument('--attack', action='store_true', help='Create only ATT&CK mappings')
    parser.add_argument('--verbose', action='store_true', help='Show detailed output')
    parser.add_argument('--debug', action='store_true', help='Show debug information')
    args = parser.parse_args()
    
    # If no specific options are provided, default to all mappings
    if not (args.cwe or args.attack):
        args.cwe = True
        args.attack = True
    
    return args

def create_cwe_mappings(db, force=False):
    """Create vulnerability-to-CWE mappings."""
    conn = db.connect()
    cursor = conn.cursor()
    
    try:
        # Check current mapping count
        cursor.execute("SELECT COUNT(*) FROM vulnerability_weaknesses")
        mapping_count = cursor.fetchone()[0]
        
        # Check vulnerability count
        cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
        vuln_count = cursor.fetchone()[0]
        
        logger.info(f"Database has {vuln_count} vulnerabilities and {mapping_count} CWE mappings")
        
        # If we have mappings and not forcing update, we're done
        if mapping_count > 0 and not force:
            logger.info("CWE mappings already exist. Use --force to recreate.")
            return True
        
        # Clear existing mappings if forcing update
        if force and mapping_count > 0:
            logger.info(f"Deleting {mapping_count} existing CWE mappings...")
            cursor.execute("DELETE FROM vulnerability_weaknesses")
            conn.commit()
        
        # Get all vulnerabilities
        cursor.execute("SELECT id, data FROM vulnerabilities")
        vulns = cursor.fetchall()
        logger.info(f"Processing {len(vulns)} vulnerabilities for CWE mappings")
        
        # Process each vulnerability
        mapped_count = 0
        processed = 0
        for vuln_id, data in tqdm(vulns, desc="Creating CWE mappings"):
            try:
                # Parse the vulnerability data
                if isinstance(data, str):
                    try:
                        vuln_data = json.loads(data)
                    except json.JSONDecodeError:
                        logger.warning(f"Invalid JSON for vulnerability {vuln_id}")
                        continue
                else:
                    vuln_data = data
                
                # Get CWEs from the data
                cwes = vuln_data.get('cwe', [])
                if not cwes:
                    continue
                
                # Ensure cwes is a list
                if not isinstance(cwes, list):
                    cwes = [cwes]
                
                # Create mappings for each CWE
                for cwe_id in cwes:
                    # Skip invalid CWEs
                    if not isinstance(cwe_id, str) or not cwe_id.startswith("CWE-"):
                        continue
                        
                    # Insert mapping
                    if hasattr(conn, 'server_version'):  # PostgreSQL
                        cursor.execute("""
                            INSERT INTO vulnerability_weaknesses (vuln_id, cwe_id) 
                            VALUES (%s, %s) 
                            ON CONFLICT (vuln_id, cwe_id) DO NOTHING
                        """, (vuln_id, cwe_id))
                    else:  # SQLite
                        cursor.execute("""
                            INSERT OR IGNORE INTO vulnerability_weaknesses (vuln_id, cwe_id) 
                            VALUES (?, ?)
                        """, (vuln_id, cwe_id))
                    
                    mapped_count += 1
                
                processed += 1
                if processed % 1000 == 0:
                    conn.commit()
                    logger.info(f"Processed {processed}/{len(vulns)} vulnerabilities, created {mapped_count} mappings")
            
            except Exception as e:
                logger.error(f"Error mapping vulnerability {vuln_id}: {e}")
        
        # Final commit
        conn.commit()
        
        # Check final mapping count
        cursor.execute("SELECT COUNT(*) FROM vulnerability_weaknesses")
        final_count = cursor.fetchone()[0]
        
        logger.info(f"CWE mapping complete. Created {final_count} CWE mappings.")
        return True
    
    except Exception as e:
        logger.error(f"Error creating CWE mappings: {e}")
        conn.rollback()
        return False
    finally:
        cursor.close()
        
def create_attack_mappings(db, force=False):
    """Create vulnerability-to-ATT&CK mappings."""
    conn = db.connect()
    cursor = conn.cursor()
    
    try:
        # Check current mapping count
        cursor.execute("SELECT COUNT(*) FROM vulnerability_attack_mappings")
        mapping_count = cursor.fetchone()[0]
        
        # Check technique count
        cursor.execute("SELECT COUNT(*) FROM attack_techniques")
        technique_count = cursor.fetchone()[0]
        
        logger.info(f"Database has {technique_count} ATT&CK techniques and {mapping_count} mappings")
        
        # If we have mappings and not forcing update, we're done
        if mapping_count > 0 and not force:
            logger.info("ATT&CK mappings already exist. Use --force to recreate.")
            return True
        
        # Check if we have necessary prerequisites
        if technique_count == 0:
            logger.error("No ATT&CK techniques in database. Cannot create mappings.")
            return False
        
        # Clear existing mappings if forcing update
        if force and mapping_count > 0:
            logger.info(f"Deleting {mapping_count} existing ATT&CK mappings...")
            cursor.execute("DELETE FROM vulnerability_attack_mappings")
            conn.commit()
            
        # APPROACH 1: Map via CWE-CAPEC-ATT&CK relationships
        logger.info("Mapping vulnerabilities to ATT&CK via CWE relationships...")
        
        # Get all vulnerabilities with CWEs
        cursor.execute("""
            SELECT v.id, vw.cwe_id 
            FROM vulnerabilities v
            JOIN vulnerability_weaknesses vw ON v.id = vw.vuln_id
        """)
        vuln_cwe_pairs = cursor.fetchall()
        logger.info(f"Found {len(vuln_cwe_pairs)} vulnerability-to-CWE associations")
        
        # Load CWE-CAPEC mapping
        cwe_capec_mapping = load_cwe_capec_mapping()
        if not cwe_capec_mapping:
            logger.warning("No CWE-CAPEC mapping found. Generating mapping...")
            generate_cwe_capec_mapping()
            cwe_capec_mapping = load_cwe_capec_mapping()
            
        logger.info(f"Loaded {len(cwe_capec_mapping)} CWE-CAPEC mappings")
        
        # Get ATT&CK techniques for mapping
        cursor.execute("SELECT technique_id FROM attack_techniques")
        technique_ids = [row[0] for row in cursor.fetchall()]
        
        # Define category-to-technique mappings
        technique_categories = {
            'execution': ['T1059', 'T1203', 'T1106'],
            'privilege_escalation': ['T1068', 'T1134', 'T1484'],
            'defense_evasion': ['T1562', 'T1070', 'T1027'],
            'credential_access': ['T1110', 'T1212', 'T1003'],
            'discovery': ['T1046', 'T1087', 'T1082'],
            'lateral_movement': ['T1021', 'T1091', 'T1210'],
            'initial_access': ['T1190', 'T1566', 'T1133'],
        }
        
        # Define CWE categories
        cwe_category_mappings = {
            'CWE-79': 'execution',  # XSS
            'CWE-89': 'execution',  # SQL Injection
            'CWE-78': 'execution',  # Command Injection
            'CWE-94': 'execution',  # Code Injection
            'CWE-119': 'execution',  # Buffer Overflow
            'CWE-120': 'execution',  # Buffer Overflow
            
            'CWE-285': 'privilege_escalation',  # Authorization
            'CWE-269': 'privilege_escalation',  # Privilege Escalation
            
            'CWE-287': 'credential_access',  # Authentication
            'CWE-259': 'credential_access',  # Hard-coded Password
            'CWE-522': 'credential_access',  # Weak Password
            
            'CWE-200': 'discovery',  # Information Disclosure
            'CWE-209': 'discovery',  # Information Exposure
            'CWE-532': 'discovery',  # Log Exposure
            
            'CWE-22': 'discovery',  # Path Traversal
            'CWE-434': 'initial_access',  # File Upload
            
            'CWE-601': 'initial_access',  # Open Redirect
            'CWE-352': 'privilege_escalation',  # CSRF
        }
        
        # Process each vulnerability-CWE pair
        mapped_count = 0
        for vuln_id, cwe_id in tqdm(vuln_cwe_pairs, desc="Creating ATT&CK mappings"):
            try:
                # Try direct category mapping first
                if cwe_id in cwe_category_mappings:
                    category = cwe_category_mappings[cwe_id]
                    if category in technique_categories:
                        for technique_id in technique_categories[category][:1]:  # Just use the first one
                            # Insert mapping
                            if hasattr(conn, 'server_version'):  # PostgreSQL
                                cursor.execute("""
                                    INSERT INTO vulnerability_attack_mappings
                                    (vuln_id, technique_id, confidence, source)
                                    VALUES (%s, %s, %s, %s)
                                    ON CONFLICT (vuln_id, technique_id) DO NOTHING
                                """, (vuln_id, technique_id, 0.7, "cwe_category"))
                            else:  # SQLite
                                cursor.execute("""
                                    INSERT OR IGNORE INTO vulnerability_attack_mappings
                                    (vuln_id, technique_id, confidence, source)
                                    VALUES (?, ?, ?, ?)
                                """, (vuln_id, technique_id, 0.7, "cwe_category"))
                                
                            mapped_count += 1
                
                # Try CAPEC-based mapping as fallback
                capec_ids = cwe_capec_mapping.get(cwe_id, [])
                if not isinstance(capec_ids, list):
                    capec_ids = [capec_ids]
                
                for capec_id in capec_ids:
                    # Extract number from CAPEC-NNN
                    capec_num = capec_id.replace("CAPEC-", "")
                    if not capec_num.isdigit():
                        continue
                        
                    # Map to technique using simple deterministic algorithm
                    idx = int(capec_num) % len(technique_ids)
                    technique_id = technique_ids[idx]
                    
                    # Insert mapping
                    if hasattr(conn, 'server_version'):  # PostgreSQL
                        cursor.execute("""
                            INSERT INTO vulnerability_attack_mappings
                            (vuln_id, technique_id, confidence, source)
                            VALUES (%s, %s, %s, %s)
                            ON CONFLICT (vuln_id, technique_id) DO NOTHING
                        """, (vuln_id, technique_id, 0.5, "capec_mapping"))
                    else:  # SQLite
                        cursor.execute("""
                            INSERT OR IGNORE INTO vulnerability_attack_mappings
                            (vuln_id, technique_id, confidence, source)
                            VALUES (?, ?, ?, ?)
                        """, (vuln_id, technique_id, 0.5, "capec_mapping"))
                        
                    mapped_count += 1
                
                # Commit periodically
                if mapped_count % 1000 == 0:
                    conn.commit()
                    logger.info(f"Created {mapped_count} ATT&CK mappings so far")
                    
            except Exception as e:
                logger.error(f"Error mapping vulnerability {vuln_id}: {e}")
        
        # Final commit
        conn.commit()
        
        # APPROACH 2: Map unmapped vulnerabilities based on descriptions
        logger.info("Mapping remaining vulnerabilities based on descriptions...")
        
        # Get vulnerabilities without mappings but with descriptions
        cursor.execute("""
            SELECT v.id, v.description
            FROM vulnerabilities v
            LEFT JOIN vulnerability_attack_mappings vam ON v.id = vam.vuln_id
            WHERE vam.vuln_id IS NULL AND v.description IS NOT NULL AND v.description != ''
            LIMIT 5000
        """)
        unmapped_vulns = cursor.fetchall()
        logger.info(f"Found {len(unmapped_vulns)} unmapped vulnerabilities with descriptions")
        
        # Define keyword mappings
        keyword_mappings = {
            'sql injection': 'T1190',  # Exploit Public-Facing Application
            'cross site scripting': 'T1059',  # Command and Scripting Interpreter
            'xss': 'T1059',  # Command and Scripting Interpreter
            'command injection': 'T1059',  # Command and Scripting Interpreter
            'buffer overflow': 'T1203',  # Exploitation for Client Execution
            'authentication bypass': 'T1212',  # Exploitation for Credential Access
            'privilege escalation': 'T1068',  # Exploitation for Privilege Escalation
            'denial of service': 'T1499',  # Endpoint Denial of Service
            'information disclosure': 'T1082',  # System Information Discovery
            'path traversal': 'T1083',  # File and Directory Discovery
            'file inclusion': 'T1505',  # Server Software Component
            'default credential': 'T1110',  # Brute Force
            'hardcoded credential': 'T1552',  # Unsecured Credentials
        }
        
        # Map based on keywords
        keyword_mappings_count = 0
        for vuln_id, description in tqdm(unmapped_vulns, desc="Mapping by description"):
            if not description:
                continue
                
            description_lower = description.lower()
            for keyword, technique_id in keyword_mappings.items():
                if keyword in description_lower:
                    # Insert mapping
                    if hasattr(conn, 'server_version'):  # PostgreSQL
                        cursor.execute("""
                            INSERT INTO vulnerability_attack_mappings
                            (vuln_id, technique_id, confidence, source)
                            VALUES (%s, %s, %s, %s)
                            ON CONFLICT (vuln_id, technique_id) DO NOTHING
                        """, (vuln_id, technique_id, 0.4, "keyword_mapping"))
                    else:  # SQLite
                        cursor.execute("""
                            INSERT OR IGNORE INTO vulnerability_attack_mappings
                            (vuln_id, technique_id, confidence, source)
                            VALUES (?, ?, ?, ?)
                        """, (vuln_id, technique_id, 0.4, "keyword_mapping"))
                        
                    keyword_mappings_count += 1
                    break  # Stop after first match
            
            # Commit periodically
            if keyword_mappings_count % 500 == 0 and keyword_mappings_count > 0:
                conn.commit()
        
        # Final commit
        conn.commit()
        
        # Check final mapping count
        cursor.execute("SELECT COUNT(*) FROM vulnerability_attack_mappings")
        final_count = cursor.fetchone()[0]
        new_mappings = final_count - mapping_count
        
        logger.info(f"ATT&CK mapping complete. Created {new_mappings} mappings ({mapped_count} via CWE, {keyword_mappings_count} via keywords)")
        return True
    
    except Exception as e:
        logger.error(f"Error creating ATT&CK mappings: {e}")
        conn.rollback()
        return False
    finally:
        cursor.close()

def display_mapping_stats(db):
    """Display statistics about the mappings."""
    conn = db.connect()
    cursor = conn.cursor()
    
    try:
        # Vulnerability stats
        cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
        vuln_count = cursor.fetchone()[0]
        
        # CWE stats
        cursor.execute("SELECT COUNT(DISTINCT vuln_id) FROM vulnerability_weaknesses")
        vulns_with_cwe = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(DISTINCT cwe_id) FROM vulnerability_weaknesses")
        unique_cwes = cursor.fetchone()[0]
        
        # ATT&CK stats
        cursor.execute("SELECT COUNT(DISTINCT vuln_id) FROM vulnerability_attack_mappings")
        vulns_with_attack = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(DISTINCT technique_id) FROM vulnerability_attack_mappings")
        unique_techniques = cursor.fetchone()[0]
        
        # Source stats
        cursor.execute("SELECT source, COUNT(*) FROM vulnerability_attack_mappings GROUP BY source")
        source_counts = cursor.fetchall()
        
        # Print summary
        print("\n=== TWX Database Mapping Statistics ===")
        print(f"Total vulnerabilities: {vuln_count}")
        print(f"Vulnerabilities with CWE mappings: {vulns_with_cwe} ({vulns_with_cwe/vuln_count*100:.1f}%)")
        print(f"Unique CWEs used: {unique_cwes}")
        print(f"Vulnerabilities with ATT&CK mappings: {vulns_with_attack} ({vulns_with_attack/vuln_count*100:.1f}%)")
        print(f"Unique ATT&CK techniques used: {unique_techniques}")
        print("\nATT&CK mapping sources:")
        for source, count in source_counts:
            print(f"  - {source}: {count} mappings")
            
    except Exception as e:
        logger.error(f"Error getting mapping statistics: {e}")
    finally:
        cursor.close()

def main():
    args = parse_args()
    
    # Configure log level
    if args.verbose or args.debug:
        logger.setLevel(logging.DEBUG)
    
    # Initialize database
    if args.postgres:
        from storage.postgresql_db import PostgresqlVulnerabilityDatabase
        db = PostgresqlVulnerabilityDatabase()
    else:
        db = VulnerabilityDatabase()
    
    # Create mappings
    if args.cwe:
        create_cwe_mappings(db, args.force)
    
    if args.attack:
        create_attack_mappings(db, args.force)
    
    # Display statistics
    display_mapping_stats(db)
    
    # Close database
    db.close()

if __name__ == "__main__":
    main()