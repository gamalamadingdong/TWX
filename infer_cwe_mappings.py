import os
import sys
import json
import logging
import argparse
from tqdm import tqdm
import pandas as pd
import re
from collections import defaultdict

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Import your existing mappers
from data_processing.cwe_vulnerability_types import CWE_VULN_TYPE_MAPPING
from analysis.attack_mapping import CWE_ATTACK_MAPPINGS

def parse_args():
    parser = argparse.ArgumentParser(description="Infer CWE mappings for vulnerabilities based on descriptions")
    parser.add_argument('--postgres', action='store_true', help='Use PostgreSQL instead of SQLite')
    parser.add_argument('--force', action='store_true', help='Force recreation of mappings')
    parser.add_argument('--limit', type=int, default=None, help='Limit the number of vulnerabilities to process')
    parser.add_argument('--verbose', action='store_true', help='Show verbose output')
    return parser.parse_args()

def infer_cwe_from_description(description, product_info=None):
    """
    Infer likely CWE IDs based on vulnerability description and product info.
    
    This function supports TWX's goal of unbiasing vulnerability data through 
    proper classification by inferring meaningful relationships between 
    vulnerabilities and weakness types.
    
    Args:
        description (str): Vulnerability description
        product_info (dict): Optional product information
        
    Returns:
        list: List of inferred CWE IDs
    """
    if not description:
        return []
    
    # Convert description to lowercase for case-insensitive matching
    desc_lower = description.lower()
    
    # Define keyword to CWE mappings - most specific first
    keyword_cwe_map = {
        # SQL injection patterns
        'sql injection': 'CWE-89',
        'sqli': 'CWE-89',
        'sql vulnerabilit': 'CWE-89',
        
        # XSS patterns
        'cross-site script': 'CWE-79',
        'cross site script': 'CWE-79',
        'xss': 'CWE-79',
        
        # Command injection
        'command injection': 'CWE-78',
        'shell command': 'CWE-78',
        'os command': 'CWE-78',
        'command execution': 'CWE-78',
        
        # Path traversal
        'path traversal': 'CWE-22',
        'directory traversal': 'CWE-22',
        '/../': 'CWE-22',
        
        # Authentication issues
        'authentication bypass': 'CWE-287',
        'missing authentication': 'CWE-306',
        'weak password': 'CWE-521',
        'hardcoded credential': 'CWE-798',
        'hardcoded password': 'CWE-798',
        
        # Buffer issues
        'buffer overflow': 'CWE-120',
        'buffer underflow': 'CWE-124',
        'stack overflow': 'CWE-121',
        'heap overflow': 'CWE-122',
        'out-of-bounds': 'CWE-125',
        'memory corruption': 'CWE-119',
        
        # Information disclosure
        'information disclosure': 'CWE-200',
        'information leak': 'CWE-200',
        'sensitive information': 'CWE-200',
        'error message': 'CWE-209',
        
        # File inclusion
        'file inclusion': 'CWE-98',
        'include file': 'CWE-98',
        
        # CSRF
        'cross-site request forgery': 'CWE-352',
        'csrf': 'CWE-352',
        'xsrf': 'CWE-352',
        
        # General web vulnerabilities
        'open redirect': 'CWE-601',
        'clickjack': 'CWE-1021',
        'click-jack': 'CWE-1021',
        
        # Cryptographic issues
        'weak crypto': 'CWE-327',
        'cryptographic': 'CWE-327',
        'encryption': 'CWE-327',
        'certificate': 'CWE-295',
        'ssl': 'CWE-295',
        'tls': 'CWE-295',
        
        # Resource issues
        'denial of service': 'CWE-400',
        'resource exhaust': 'CWE-400',
        'dos ': 'CWE-400',
        
        # Insecure deserialization
        'deseriali': 'CWE-502',
        'unseriali': 'CWE-502',
        
        # Access control
        'privilege escalation': 'CWE-269',
        'access control': 'CWE-284',
        'authorization': 'CWE-285',
        'permission': 'CWE-732',
        
        # Race conditions
        'race condition': 'CWE-362',
        'toctou': 'CWE-367',
        'time-of-check': 'CWE-367',
        
        # Use after free
        'use after free': 'CWE-416',
        'uaf': 'CWE-416',
        'double free': 'CWE-415',
        
        # Null pointer
        'null pointer': 'CWE-476',
        'null dereference': 'CWE-476',
        
        # Integer issues
        'integer overflow': 'CWE-190',
        'integer underflow': 'CWE-191',
    }
    
    # Find all matching keywords and their CWEs
    matched_cwes = []
    
    for keyword, cwe in keyword_cwe_map.items():
        if keyword in desc_lower:
            if cwe not in matched_cwes:
                matched_cwes.append(cwe)
    
    # If product info exists, check for known platform-specific vulnerabilities
    if product_info:
        product_name = str(product_info.get('product', '')).lower()
        vendor_name = str(product_info.get('vendor', '')).lower()
        
        # Web server-specific vulnerabilities
        if any(s in product_name for s in ['apache', 'nginx', 'iis', 'tomcat', 'weblogic']):
            if 'buffer' in desc_lower or 'overflow' in desc_lower:
                if 'CWE-119' not in matched_cwes:
                    matched_cwes.append('CWE-119')
            if any(s in desc_lower for s in ['config', 'permission', 'access']):
                if 'CWE-284' not in matched_cwes:
                    matched_cwes.append('CWE-284')
        
        # Database-specific vulnerabilities
        if any(s in product_name for s in ['sql', 'mysql', 'oracle', 'postgresql', 'mongodb']):
            if 'inject' in desc_lower:
                if 'CWE-89' not in matched_cwes:
                    matched_cwes.append('CWE-89')
            if 'authentication' in desc_lower:
                if 'CWE-287' not in matched_cwes:
                    matched_cwes.append('CWE-287')
                    
        # Browser-specific vulnerabilities
        if any(s in product_name for s in ['chrome', 'firefox', 'safari', 'edge', 'ie']):
            if 'script' in desc_lower:
                if 'CWE-79' not in matched_cwes:
                    matched_cwes.append('CWE-79')
            if 'same-origin' in desc_lower or 'same origin' in desc_lower:
                if 'CWE-346' not in matched_cwes:
                    matched_cwes.append('CWE-346')
    
    # If no CWEs were identified, try to assign a general category
    if not matched_cwes:
        # Check for general vulnerability indicators
        if any(term in desc_lower for term in ['overflow', 'buffer', 'memory', 'heap', 'stack']):
            matched_cwes.append('CWE-119')  # Memory Corruption
        elif any(term in desc_lower for term in ['inject', 'sql', 'command', 'script']):
            matched_cwes.append('CWE-74')   # Injection
        elif any(term in desc_lower for term in ['authentication', 'password', 'login', 'credential']):
            matched_cwes.append('CWE-287')  # Authentication Issues
        elif any(term in desc_lower for term in ['access control', 'permission', 'privilege', 'authorization']):
            matched_cwes.append('CWE-284')  # Access Control
        elif any(term in desc_lower for term in ['information disclosure', 'leak', 'sensitive']):
            matched_cwes.append('CWE-200')  # Information Disclosure
        elif any(term in desc_lower for term in ['denial of service', 'dos', 'crash']):
            matched_cwes.append('CWE-400')  # Resource Management
            
    return matched_cwes

def infer_all_cwe_mappings(db, force=False, limit=None):
    """
    Create vulnerability-to-CWE mappings by inferring from descriptions.
    """
    is_postgres = db.__class__.__name__ == 'PostgresqlVulnerabilityDatabase'
    
    conn = db.connect()
    cursor = conn.cursor()
    
    # Start by checking existing mappings
    cursor.execute("SELECT COUNT(*) FROM vulnerability_weaknesses")
    existing_count = cursor.fetchone()[0]
    logger.info(f"Current vulnerability-to-CWE mappings: {existing_count}")
    
    # Get count of vulnerabilities
    cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
    vuln_count = cursor.fetchone()[0]
    logger.info(f"Total vulnerabilities in database: {vuln_count}")
    
    # If we have complete mappings and not forcing update, skip
    cursor.execute("""
        SELECT COUNT(DISTINCT vuln_id) FROM vulnerability_weaknesses
    """)
    mapped_vulns = cursor.fetchone()[0]
    
    if mapped_vulns >= vuln_count and not force:
        logger.info("All vulnerabilities already have CWE mappings. Use --force to recreate.")
        return True
    
    # If force is true, clear existing mappings
    if force and existing_count > 0:
        logger.info(f"Removing {existing_count} existing CWE mappings...")
        cursor.execute("DELETE FROM vulnerability_weaknesses")
        conn.commit()
    
    # Get vulnerabilities without CWE mappings
    if limit:
        if is_postgres:
            cursor.execute("""
                SELECT v.id, v.description, v.data 
                FROM vulnerabilities v
                LEFT JOIN vulnerability_weaknesses vw ON v.id = vw.vuln_id
                WHERE vw.vuln_id IS NULL
                LIMIT %s
            """, (limit,))
        else:
            cursor.execute("""
                SELECT v.id, v.description, v.data 
                FROM vulnerabilities v
                LEFT JOIN vulnerability_weaknesses vw ON v.id = vw.vuln_id
                WHERE vw.vuln_id IS NULL
                LIMIT ?
            """, (limit,))
    else:
        cursor.execute("""
            SELECT v.id, v.description, v.data 
            FROM vulnerabilities v
            LEFT JOIN vulnerability_weaknesses vw ON v.id = vw.vuln_id
            WHERE vw.vuln_id IS NULL
        """)
    
    vulnerabilities = cursor.fetchall()
    logger.info(f"Processing {len(vulnerabilities)} vulnerabilities without CWE mappings")
    
    # Create mappings based on description inference
    new_mappings = 0
    stats = defaultdict(int)
    
    for vuln_id, description, data in tqdm(vulnerabilities, desc="Inferring CWE mappings"):
        # Extract product info if available
        product_info = None
        if data:
            if isinstance(data, str):
                try:
                    data_dict = json.loads(data)
                    products = data_dict.get('products', [])
                    if products and len(products) > 0:
                        product_info = products[0]
                except:
                    pass
            elif isinstance(data, dict):
                products = data.get('products', [])
                if products and len(products) > 0:
                    product_info = products[0]
        
        # Infer CWEs from description
        inferred_cwes = infer_cwe_from_description(description, product_info)
        
        if not inferred_cwes:
            # Default case - if we can't infer any CWE, use a general one
            inferred_cwes = ['CWE-1035']  # General vulnerability
        
        # Insert mappings
        for cwe_id in inferred_cwes:
            try:
                if is_postgres:
                    cursor.execute("""
                        INSERT INTO vulnerability_weaknesses (vuln_id, cwe_id, confidence, source)
                        VALUES (%s, %s, %s, %s)
                        ON CONFLICT (vuln_id, cwe_id) DO NOTHING
                    """, (vuln_id, cwe_id, 0.7, "inferred"))
                else:
                    cursor.execute("""
                        INSERT OR IGNORE INTO vulnerability_weaknesses (vuln_id, cwe_id, confidence, source)
                        VALUES (?, ?, ?, ?)
                    """, (vuln_id, cwe_id, 0.7, "inferred"))
                
                new_mappings += 1
                stats[cwe_id] += 1
                
            except Exception as e:
                logger.error(f"Error creating mapping for {vuln_id} to {cwe_id}: {e}")
        
        # Commit periodically
        if new_mappings % 1000 == 0:
            conn.commit()
            logger.info(f"Created {new_mappings} CWE mappings so far")
    
    # Final commit
    conn.commit()
    
    # Get final count
    cursor.execute("SELECT COUNT(*) FROM vulnerability_weaknesses")
    final_count = cursor.fetchone()[0]
    
    # Show top 10 inferred CWEs
    logger.info("\nTop 10 inferred CWEs:")
    top_cwes = sorted(stats.items(), key=lambda x: x[1], reverse=True)[:10]
    for cwe_id, count in top_cwes:
        # Get CWE name if available
        cursor.execute("SELECT name FROM weaknesses WHERE id = %s", (cwe_id,) if is_postgres else (cwe_id,))
        result = cursor.fetchone()
        cwe_name = result[0] if result else "Unknown"
        logger.info(f"  {cwe_id}: {count} occurrences - {cwe_name}")
    
    logger.info(f"\nCWE mapping complete. Created {final_count - existing_count} new mappings.")
    logger.info(f"Total CWE mappings: {final_count}")
    
    # Close cursor and connection
    cursor.close()
    
    return True

def main():
    args = parse_args()
    
    # Initialize appropriate database
    if args.postgres:
        from storage.postgresql_db import PostgresqlVulnerabilityDatabase
        db = PostgresqlVulnerabilityDatabase()
    else:
        from storage.vulnerability_db import VulnerabilityDatabase
        db = VulnerabilityDatabase()
    
    # Infer CWE mappings
    infer_all_cwe_mappings(db, args.force, args.limit)
    
    # Now create ATT&CK mappings based on the inferred CWEs
    try:
        from storage.populate_database import create_attack_mappings
        logger.info("Creating vulnerability-to-ATT&CK mappings based on inferred CWEs...")
        create_attack_mappings(db, args.force)
    except Exception as e:
        logger.error(f"Error creating ATT&CK mappings: {e}")
    
    # Show final stats
    conn = db.connect()
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
        total_vulns = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(DISTINCT vuln_id) FROM vulnerability_weaknesses")
        mapped_vulns = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM vulnerability_weaknesses")
        total_mappings = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(DISTINCT vuln_id) FROM vulnerability_attack_mappings")
        attack_mapped_vulns = cursor.fetchone()[0]
        
        logger.info("\n=== TWX Vulnerability Mapping Statistics ===")
        logger.info(f"Total vulnerabilities: {total_vulns}")
        logger.info(f"Vulnerabilities with CWE mappings: {mapped_vulns} ({mapped_vulns/total_vulns*100:.1f}%)")
        logger.info(f"Total CWE mappings: {total_mappings} (avg {total_mappings/mapped_vulns:.2f} per vulnerability)")
        logger.info(f"Vulnerabilities with ATT&CK mappings: {attack_mapped_vulns} ({attack_mapped_vulns/total_vulns*100:.1f}%)")
        logger.info("========================================")
        
    except Exception as e:
        logger.error(f"Error getting final statistics: {e}")
    finally:
        cursor.close()
        db.close()

if __name__ == "__main__":
    main()