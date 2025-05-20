"""
Fix missing CWE mappings by inferring them from vulnerability descriptions.
This supports TWX's goal of unbiasing vulnerability data through proper classification.
"""

import os
import sys
import json
import logging
import argparse
from tqdm import tqdm

# Set up proper imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Import your existing vulnerability type mappings
from data_processing.cwe_vulnerability_types import CWE_VULN_TYPE_MAPPING, get_vulnerability_type

def parse_args():
    parser = argparse.ArgumentParser(description='Fix missing CWE mappings by inferring from descriptions')
    parser.add_argument('--postgres', action='store_true', help='Use PostgreSQL database')
    parser.add_argument('--force', action='store_true', help='Force recreate all mappings')
    parser.add_argument('--batch-size', type=int, default=10000, help='Batch size for processing')
    return parser.parse_args()

def infer_cwe_from_description(description):
    """
    Infer the most likely CWE type from a vulnerability description.
    Uses keyword matching against common vulnerability patterns.
    """
    if not description:
        return []
    
    description = description.lower()
    
    # Map keywords to CWE IDs - ordered by specificity (most specific first)
    keyword_cwe_map = {
        # SQL Injection
        'sql injection': 'CWE-89',
        'sqli ': 'CWE-89',
        'sql command': 'CWE-89',
        
        # XSS
        'cross-site scripting': 'CWE-79',
        'cross site scripting': 'CWE-79',
        'xss': 'CWE-79',
        
        # Command Injection
        'command injection': 'CWE-78',
        'os command': 'CWE-78',
        'shell injection': 'CWE-78',
        'shell command': 'CWE-78',
        
        # Path Traversal
        'path traversal': 'CWE-22',
        'directory traversal': 'CWE-22',
        'file inclusion': 'CWE-98',
        '/../': 'CWE-22',
        
        # Memory Safety
        'buffer overflow': 'CWE-120',
        'stack overflow': 'CWE-121',
        'heap overflow': 'CWE-122',
        'use after free': 'CWE-416',
        'double free': 'CWE-415',
        'null pointer': 'CWE-476',
        'memory corruption': 'CWE-119',
        
        # Authentication
        'authentication bypass': 'CWE-287',
        'bypass authentication': 'CWE-287', 
        'weak password': 'CWE-521',
        'hardcoded password': 'CWE-798',
        'hardcoded credential': 'CWE-798',
        
        # Info Disclosure
        'information disclosure': 'CWE-200',
        'sensitive information': 'CWE-200',
        'information leak': 'CWE-200',
        
        # Cryptographic Issues
        'weak encryption': 'CWE-327',
        'weak crypto': 'CWE-327',
        'certificate validation': 'CWE-295',
        'ssl certificate': 'CWE-295',
        
        # Access Control
        'missing authorization': 'CWE-285',
        'improper access control': 'CWE-284',
        'privilege escalation': 'CWE-269',
        
        # Web-specific
        'csrf': 'CWE-352',
        'cross-site request forgery': 'CWE-352',
        'open redirect': 'CWE-601',
        'xxe': 'CWE-611',
        
        # General
        'injection': 'CWE-74',
        'deserialization': 'CWE-502',
        'race condition': 'CWE-362',
        'denial of service': 'CWE-400'
    }
    
    # Find all matching CWEs
    matched_cwes = []
    for keyword, cwe_id in keyword_cwe_map.items():
        if keyword in description and cwe_id not in matched_cwes:
            matched_cwes.append(cwe_id)
    
    # If nothing specific was found, try to determine a general vulnerability class
    if not matched_cwes:
        if 'overflow' in description or 'memory' in description:
            matched_cwes.append('CWE-119')  # Memory Safety
        elif 'injection' in description or 'script' in description:
            matched_cwes.append('CWE-74')   # Injection
        elif 'auth' in description or 'password' in description:
            matched_cwes.append('CWE-287')  # Authentication
        elif 'permission' in description or 'privilege' in description:
            matched_cwes.append('CWE-284')  # Access Control
        elif 'information' in description or 'disclosure' in description:
            matched_cwes.append('CWE-200')  # Information Disclosure
    
    return matched_cwes

def create_inferred_cwe_mappings(db, force=False, batch_size=10000):
    """Create CWE mappings by inferring them from vulnerability descriptions."""
    is_postgres = db.__class__.__name__ == 'PostgresqlVulnerabilityDatabase'
    conn = db.connect()
    cursor = conn.cursor()
    
    try:
        # Check if mappings already exist
        cursor.execute("SELECT COUNT(*) FROM vulnerability_weaknesses")
        existing_count = cursor.fetchone()[0]
        logger.info(f"Found {existing_count} existing CWE mappings")
        
        # Skip if mappings exist and we're not forcing recreation
        if existing_count > 0 and not force:
            logger.info("CWE mappings already exist. Use --force to recreate.")
            return True
        
        # If force is true, delete existing mappings
        if force and existing_count > 0:
            logger.info(f"Deleting {existing_count} existing CWE mappings...")
            cursor.execute("DELETE FROM vulnerability_weaknesses")
            conn.commit()
        
        # Get total count of vulnerabilities
        cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
        total_vulns = cursor.fetchone()[0]
        logger.info(f"Found {total_vulns} vulnerabilities to process")
        
        # Process in batches to avoid memory issues
        offset = 0
        total_mapped = 0
        cwe_stats = {}
        
        while offset < total_vulns:
            # Get batch of vulnerabilities
            if is_postgres:
                cursor.execute(f"SELECT id, description FROM vulnerabilities LIMIT {batch_size} OFFSET {offset}")
            else:
                cursor.execute(f"SELECT id, description FROM vulnerabilities LIMIT {batch_size} OFFSET {offset}")
            
            vulnerabilities = cursor.fetchall()
            if not vulnerabilities:
                break
                
            logger.info(f"Processing batch of {len(vulnerabilities)} vulnerabilities (offset {offset})")
            
            # Process each vulnerability
            batch_mapped = 0
            insertion_errors = 0
            
            # Use a separate transaction for each vulnerability to prevent cascading errors
            for vuln_id, description in tqdm(vulnerabilities, desc="Inferring CWEs"):
                # Skip if no description
                if not description:
                    continue
                
                # Create a fresh cursor for each vulnerability to isolate transaction errors
                if is_postgres:
                    local_cursor = conn.cursor()
                else:
                    local_cursor = cursor
                    
                try:
                    # Infer CWEs from description
                    inferred_cwes = infer_cwe_from_description(description)
                    
                    if not inferred_cwes:
                        # If no CWEs could be inferred, assign a generic one
                        inferred_cwes = ['CWE-1035']  # Other
                    
                    # Create mappings
                    for cwe_id in inferred_cwes:
                        try:
                            if is_postgres:
                                local_cursor.execute("""
                                    INSERT INTO vulnerability_weaknesses (vuln_id, cwe_id, confidence, source) 
                                    VALUES (%s, %s, %s, %s)
                                    ON CONFLICT (vuln_id, cwe_id) DO NOTHING
                                """, (vuln_id, cwe_id, 0.7, "inferred"))
                            else:
                                local_cursor.execute("""
                                    INSERT OR IGNORE INTO vulnerability_weaknesses (vuln_id, cwe_id, confidence, source)
                                    VALUES (?, ?, ?, ?)
                                """, (vuln_id, cwe_id, 0.7, "inferred"))
                            
                            # Update stats
                            cwe_stats[cwe_id] = cwe_stats.get(cwe_id, 0) + 1
                            batch_mapped += 1
                            total_mapped += 1
                            
                        except Exception as e:
                            # Log the specific insertion error
                            logger.error(f"Error mapping {vuln_id} to {cwe_id}: {e}")
                            insertion_errors += 1
                            
                            # For PostgreSQL, we need to rollback on error
                            if is_postgres:
                                conn.rollback()
                    
                    # Commit this vulnerability's mappings immediately (PostgreSQL only)
                    if is_postgres:
                        conn.commit()
                        
                except Exception as e:
                    # Handle per-vulnerability errors
                    logger.error(f"Error processing vulnerability {vuln_id}: {e}")
                    if is_postgres:
                        conn.rollback()
                finally:
                    # Close the local cursor if using PostgreSQL
                    if is_postgres and local_cursor != cursor:
                        local_cursor.close()
            
            # Commit batch if using SQLite (PostgreSQL commits after each vulnerability)
            if not is_postgres:
                conn.commit()
                
            logger.info(f"Created {batch_mapped} CWE mappings in this batch ({insertion_errors} errors)")
            
            # Move to next batch
            offset += batch_size
        
        # Show stats for top CWEs
        logger.info("\nTop 10 inferred CWE types:")
        top_cwes = sorted(cwe_stats.items(), key=lambda x: x[1], reverse=True)[:10]
        for cwe_id, count in top_cwes:
            vuln_type = get_vulnerability_type(cwe_id)
            logger.info(f"  {cwe_id} ({vuln_type}): {count} vulnerabilities")
        
        logger.info(f"\nCreated a total of {total_mapped} CWE mappings")
        return True
        
    except Exception as e:
        logger.error(f"Error creating inferred CWE mappings: {e}")
        if is_postgres:
            conn.rollback()
        return False
    finally:
        cursor.close()

def main():
    args = parse_args()
    
    # Initialize the appropriate database
    if args.postgres:
        from storage.postgresql_db import PostgresqlVulnerabilityDatabase
        db = PostgresqlVulnerabilityDatabase()
        logger.info("Using PostgreSQL database")
    else:
        from storage.vulnerability_db import VulnerabilityDatabase
        db = VulnerabilityDatabase()
        logger.info("Using SQLite database")
    
    # Create the inferred CWE mappings
    success = create_inferred_cwe_mappings(db, args.force, args.batch_size)
    
    if success:
        logger.info("Successfully created inferred CWE mappings")
        
        # Now proceed with creating ATT&CK mappings
        try:
            logger.info("Creating vulnerability-to-ATT&CK mappings based on inferred CWEs...")
            from storage.populate_database import create_attack_mappings
            create_attack_mappings(db, args.force)
        except Exception as e:
            logger.error(f"Error creating ATT&CK mappings: {e}")
    else:
        logger.error("Failed to create inferred CWE mappings")
    
    # Show summary statistics
    conn = db.connect()
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
        total_vulns = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(DISTINCT vuln_id) FROM vulnerability_weaknesses")
        mapped_vulns = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM vulnerability_weaknesses")
        total_mappings = cursor.fetchone()[0]
        
        logger.info("\n=== TWX Vulnerability Mapping Statistics ===")
        logger.info(f"Total vulnerabilities: {total_vulns}")
        logger.info(f"Vulnerabilities with CWE mappings: {mapped_vulns} ({mapped_vulns/total_vulns*100:.1f}%)")
        logger.info(f"Total CWE mappings: {total_mappings} (avg {total_mappings/mapped_vulns if mapped_vulns else 0:.2f} per vulnerability)")
        
        # Show distribution of vulnerability types
        cursor.execute("""
            SELECT cwe_id, COUNT(*) as count 
            FROM vulnerability_weaknesses 
            GROUP BY cwe_id 
            ORDER BY count DESC 
            LIMIT 10
        """)
        
        top_cwes = cursor.fetchall()
        logger.info("\nTop 10 CWE types by frequency:")
        for cwe_id, count in top_cwes:
            vuln_type = get_vulnerability_type(cwe_id)
            logger.info(f"  {cwe_id} ({vuln_type}): {count} vulnerabilities")
        
    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
    finally:
        cursor.close()
        db.close()

if __name__ == "__main__":
    main()