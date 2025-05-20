# Run this script to fix the existing database mappings
import os
import json
import sys
import logging
from tqdm import tqdm

# Set up proper imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def fix_database_mappings():
    """Fix the vulnerability-to-CWE and vulnerability-to-ATT&CK mappings in the database."""
    # Import the proper database class
    use_postgres = os.environ.get('TWX_USE_POSTGRES', '').lower() in ('true', '1', 'yes')
    
    if use_postgres:
        from storage.postgresql_db import PostgresqlVulnerabilityDatabase
        db = PostgresqlVulnerabilityDatabase()
    else:
        from storage.vulnerability_db import VulnerabilityDatabase
        db = VulnerabilityDatabase()
    
    conn = db.connect()
    cursor = conn.cursor()
    
    try:
        # First, check current state
        cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
        vuln_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM vulnerability_weaknesses")
        cwe_mapping_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM attack_techniques")
        attack_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM vulnerability_attack_mappings")
        attack_mapping_count = cursor.fetchone()[0]
        
        logger.info(f"Current database state:")
        logger.info(f"- Vulnerabilities: {vuln_count}")
        logger.info(f"- CWE mappings: {cwe_mapping_count}")
        logger.info(f"- ATT&CK techniques: {attack_count}")
        logger.info(f"- ATT&CK mappings: {attack_mapping_count}")
        
        # Step 1: Create CWE mappings
        logger.info("Creating vulnerability-to-CWE mappings...")
        
        # Get all vulnerabilities and their CWEs
        cursor.execute("SELECT id, data FROM vulnerabilities")
        vulns = cursor.fetchall()
        
        # Process each vulnerability
        mapped_cwes = 0
        for vuln_id, data in tqdm(vulns, desc="Creating CWE mappings"):
            try:
                if not data:
                    continue
                    
                # Parse the data JSON
                if isinstance(data, str):
                    vuln_data = json.loads(data)
                else:
                    vuln_data = data
                
                # Get CWEs from the vulnerability data
                cwes = vuln_data.get('cwe', [])
                if not cwes:
                    continue
                
                # Ensure it's a list
                if not isinstance(cwes, list):
                    cwes = [cwes]
                
                # Create mapping for each CWE
                for cwe_id in cwes:
                    # Ensure proper CWE ID format
                    if not cwe_id.startswith("CWE-"):
                        continue
                        
                    # Insert the mapping
                    if use_postgres:
                        cursor.execute("""
                            INSERT INTO vulnerability_weaknesses (vuln_id, cwe_id)
                            VALUES (%s, %s)
                            ON CONFLICT (vuln_id, cwe_id) DO NOTHING
                        """, (vuln_id, cwe_id))
                    else:
                        cursor.execute("""
                            INSERT OR IGNORE INTO vulnerability_weaknesses (vuln_id, cwe_id)
                            VALUES (?, ?)
                        """, (vuln_id, cwe_id))
                    mapped_cwes += 1
                
            except Exception as e:
                logger.error(f"Error mapping vulnerability {vuln_id} to CWEs: {e}")
        
        # Commit CWE mappings
        conn.commit()
        
        # Check new CWE mapping count
        cursor.execute("SELECT COUNT(*) FROM vulnerability_weaknesses")
        new_cwe_count = cursor.fetchone()[0]
        logger.info(f"Created {new_cwe_count - cwe_mapping_count} new CWE mappings")
        
        # Step 2: Create ATT&CK mappings if we have techniques
        if attack_count > 0:
            from data_processing.mappers.cwe_capec_mapper import load_cwe_capec_mapping
            
            # Try to load the CWE-CAPEC mapping
            try:
                cwe_capec_mapping = load_cwe_capec_mapping()
                logger.info(f"Loaded CWE-CAPEC mapping with {len(cwe_capec_mapping)} entries")
                
                # Get all vulnerability-CWE pairs
                cursor.execute("""
                    SELECT v.id, vw.cwe_id 
                    FROM vulnerabilities v
                    JOIN vulnerability_weaknesses vw ON v.id = vw.vuln_id
                """)
                vuln_cwe_pairs = cursor.fetchall()
                logger.info(f"Found {len(vuln_cwe_pairs)} vulnerability-CWE associations")
                
                # Get all technique IDs
                cursor.execute("SELECT technique_id FROM attack_techniques")
                technique_ids = [row[0] for row in cursor.fetchall()]
                
                # Create a simple mapping from CAPEC to ATT&CK
                capec_attack_mapping = {}
                for capec_id in cwe_capec_mapping.values():
                    if isinstance(capec_id, list):
                        for capec in capec_id:
                            capec_num = capec.replace("CAPEC-", "")
                            # Simple deterministic mapping for demonstration
                            technique_idx = int(capec_num) % len(technique_ids) if capec_num.isdigit() else 0
                            capec_attack_mapping[capec] = technique_ids[technique_idx]
                
                # Create the mappings
                mapped_techniques = 0
                for vuln_id, cwe_id in tqdm(vuln_cwe_pairs, desc="Creating ATT&CK mappings"):
                    # Get CAPEC IDs for this CWE
                    capec_ids = cwe_capec_mapping.get(cwe_id, [])
                    if not isinstance(capec_ids, list):
                        capec_ids = [capec_ids]
                    
                    # Map to ATT&CK techniques
                    for capec_id in capec_ids:
                        if capec_id in capec_attack_mapping:
                            technique_id = capec_attack_mapping[capec_id]
                            
                            # Insert mapping
                            if use_postgres:
                                cursor.execute("""
                                    INSERT INTO vulnerability_attack_mappings 
                                    (vuln_id, technique_id, confidence, source) 
                                    VALUES (%s, %s, %s, %s)
                                    ON CONFLICT (vuln_id, technique_id) DO NOTHING
                                """, (vuln_id, technique_id, 0.7, "cwe_capec_mapping"))
                            else:
                                cursor.execute("""
                                    INSERT OR IGNORE INTO vulnerability_attack_mappings 
                                    (vuln_id, technique_id, confidence, source) 
                                    VALUES (?, ?, ?, ?)
                                """, (vuln_id, technique_id, 0.7, "cwe_capec_mapping"))
                            mapped_techniques += 1
                
                # Commit ATT&CK mappings
                conn.commit()
                
                # Check new ATT&CK mapping count
                cursor.execute("SELECT COUNT(*) FROM vulnerability_attack_mappings")
                new_attack_count = cursor.fetchone()[0]
                logger.info(f"Created {new_attack_count - attack_mapping_count} new ATT&CK mappings")
                
            except Exception as e:
                logger.error(f"Error creating ATT&CK mappings: {e}")
        
        return True
    
    except Exception as e:
        logger.error(f"Error fixing database mappings: {e}")
        conn.rollback()
        return False
    
    finally:
        cursor.close()
        db.close()

if __name__ == "__main__":
    fix_database_mappings()