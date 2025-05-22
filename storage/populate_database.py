import os
import json
import sys
import re
import time
import argparse
import xml.etree.ElementTree as ET
from pathlib import Path
import pandas as pd
import logging
from datetime import datetime
from tqdm import tqdm
import psycopg2

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from storage.vulnerability_db import VulnerabilityDatabase
from data_processing.parse_attack import parse_attack_data
from data_processing.parse_cwe import parse_cwe_xml
from data_processing.parse_cve import parse_cve_record
from data_processing.parse_nvd import parse_nvd_record
from data_processing.mappers.cwe_capec_mapper import load_cwe_capec_mapping, map_cwe_to_capec

# Set up logging
log_dir = "logs"
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, f"populate_db_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def parse_args():
    """Parse command line arguments for targeted updates."""
    parser = argparse.ArgumentParser(description='Populate or update the vulnerability database')
    parser.add_argument('--all', action='store_true', help='Process all data sources')
    parser.add_argument('--cve', action='store_true', help='Process CVE data')
    parser.add_argument('--nvd', action='store_true', help='Process NVD data')
    parser.add_argument('--cwe', action='store_true', help='Process CWE data')
    parser.add_argument('--attack', action='store_true', help='Process ATT&CK data')
    parser.add_argument('--capec', action='store_true', help='Process CAPEC data')
    parser.add_argument('--mappings', action='store_true', help='Create/update vulnerability-to-ATT&CK mappings')
    parser.add_argument('--unify', action='store_true', help='Create unified vulnerability records from CVE and NVD')
    parser.add_argument('--force', action='store_true', help='Force update even if data exists')
    parser.add_argument('--export', action='store_true', help='Export classification data')
    parser.add_argument('--verify', action='store_true', help='Verify database integrity')
    parser.add_argument('--debug', action='store_true', help='Show debug information')
    parser.add_argument('--schema', action='store_true', help='Export database schema to SQL file')
    parser.add_argument('--schema-path', type=str, default="documentation/db_schema.sql", 
                       help='Path to save the database schema')
    parser.add_argument('--raw-dir', type=str, default="data_collection/raw_data",
                       help='Directory containing raw data files')
    parser.add_argument('--processed-dir', type=str, default="data_collection/processed_data",
                       help='Directory to store processed data files')
    parser.add_argument('--min-year', type=int, default=2021,
                       help='Minimum year for CVE data processing (default: 2021)')
    args = parser.parse_args()
    
    # If no specific options are provided, default to --all
    if not (args.all or args.cve or args.nvd or args.cwe or args.attack or args.capec or 
            args.mappings or args.export or args.unify or args.verify):
        args.all = True
    
    return args


def verify_database_integrity(db):
    """
    Verify the integrity of the vulnerability database.
    
    This function performs several checks:
    1. Table existence and row counts
    2. Referential integrity between tables
    3. Data quality checks (missing fields, malformed data)
    4. Consistency between related data sources
    
    Args:
        db: Database connection object
        
    Returns:
        bool: True if database passes integrity checks, False otherwise
    """
    conn = db.connect()
    cursor = conn.cursor()
    
    try:
        logger.info("Verifying database integrity...")
        
        # 1. Check table existence and row counts
        tables = [
            "vulnerabilities", 
            "weaknesses", 
            "attack_techniques", 
            "vulnerability_weaknesses", 
            "vulnerability_attack_mappings",
            "metrics", 
            "vuln_references"
        ]
        
        table_counts = {}
        missing_tables = []
        
        for table in tables:
            try:
                cursor.execute(f"SELECT COUNT(*) FROM {table}")
                count = cursor.fetchone()[0]
                table_counts[table] = count
                logger.info(f"Table '{table}': {count} rows")
            except Exception as e:
                missing_tables.append(table)
                logger.warning(f"Table '{table}' doesn't exist or can't be queried: {e}")
        
        if missing_tables:
            logger.error(f"Missing tables: {', '.join(missing_tables)}")
            return False
            
        # 2. Check referential integrity
        integrity_checks = [
            {
                "name": "Vulnerability-Weakness mappings",
                "sql": """
                    SELECT COUNT(*) FROM vulnerability_weaknesses vw
                    LEFT JOIN vulnerabilities v ON vw.vuln_id = v.id
                    WHERE v.id IS NULL
                """,
                "error_msg": "orphaned CWE mappings"
            },
            {
                "name": "Vulnerability-ATT&CK mappings",
                "sql": """
                    SELECT COUNT(*) FROM vulnerability_attack_mappings vam
                    LEFT JOIN vulnerabilities v ON vam.vuln_id = v.id
                    WHERE v.id IS NULL
                """,
                "error_msg": "orphaned ATT&CK mappings"
            },
            {
                "name": "Vulnerability-Metrics mappings",
                "sql": """
                    SELECT COUNT(*) FROM metrics vm
                    LEFT JOIN vulnerabilities v ON vm.vuln_id = v.id
                    WHERE v.id IS NULL
                """,
                "error_msg": "orphaned metrics"
            },
            {
                "name": "Vulnerability-References mappings",
                "sql": """
                    SELECT COUNT(*) FROM vuln_references vr
                    LEFT JOIN vulnerabilities v ON vr.vuln_id = v.id
                    WHERE v.id IS NULL
                """,
                "error_msg": "orphaned references"
            },
            {
                "name": "Vulnerability-Patch data",
                "sql": """
                    SELECT COUNT(*) FROM vulnerabilities 
                    WHERE has_patch = TRUE AND patch_date IS NULL
                """,
                "error_msg": "vulnerabilities with has_patch=TRUE but no patch_date"
            }
        ]
        
        integrity_issues = False
        for check in integrity_checks:
            if check["name"].split("-")[0].lower() in table_counts and check["name"].split("-")[1].lower() in table_counts:
                try:
                    cursor.execute(check["sql"])
                    orphaned = cursor.fetchone()[0]
                    if orphaned > 0:
                        logger.error(f"Integrity issue: {orphaned} {check['error_msg']}")
                        integrity_issues = True
                    else:
                        logger.debug(f"Integrity check '{check['name']}': OK")
                except Exception as e:
                    logger.error(f"Error running integrity check '{check['name']}': {e}")
                    integrity_issues = True
        
        # 3. Data quality checks
        quality_checks = [
            {
                "name": "Vulnerabilities without description",
                "sql": "SELECT COUNT(*) FROM vulnerabilities WHERE description IS NULL OR description = ''",
                "warning_threshold": 10
            },
            {
                "name": "Weaknesses without name",
                "sql": "SELECT COUNT(*) FROM weaknesses WHERE name IS NULL OR name = ''",
                "warning_threshold": 5
            },
            {
                "name": "ATT&CK techniques without name",
                "sql": "SELECT COUNT(*) FROM attack_techniques WHERE name IS NULL OR name = ''",
                "warning_threshold": 5
            },
            {
                "name": "Vulnerabilities without CWE mappings",
                "sql": """
                    SELECT COUNT(*) FROM vulnerabilities v
                    LEFT JOIN vulnerability_weaknesses vw ON v.id = vw.vuln_id
                    WHERE vw.vuln_id IS NULL
                """,
                "warning_threshold": 100  # It's common for some CVEs to lack CWE mappings
            }
        ]
        
        quality_issues = False
        for check in quality_checks:
            try:
                cursor.execute(check["sql"])
                count = cursor.fetchone()[0]
                if count > check["warning_threshold"]:
                    logger.warning(f"Data quality issue: {count} {check['name']} (threshold: {check['warning_threshold']})")
                    quality_issues = True
                else:
                    logger.debug(f"Data quality check '{check['name']}': OK ({count} instances)")
            except Exception as e:
                logger.error(f"Error running data quality check '{check['name']}': {e}")
                quality_issues = True
        
        # 4. Consistency between related data (sample checks)
        consistency_checks = []
        
        # CVSS scores range check (base score should be 0-10)
        consistency_checks.append({
            "name": "CVSS scores out of range",
            "sql": "SELECT COUNT(*) FROM metrics WHERE base_score < 0 OR base_score > 10",
            "error_msg": "CVSS scores outside valid range (0-10)"
        })
        
        # CWE ID format check
        consistency_checks.append({
            "name": "CWE ID format",
            "sql": "SELECT COUNT(*) FROM weaknesses WHERE cwe_id NOT LIKE 'CWE-%'",
            "error_msg": "CWE IDs with invalid format (should be 'CWE-number')"
        })
        
        # ATT&CK technique ID format check
        consistency_checks.append({
            "name": "ATT&CK technique ID format",
            "sql": "SELECT COUNT(*) FROM attack_techniques WHERE technique_id NOT LIKE 'T%'",
            "error_msg": "ATT&CK technique IDs with invalid format (should start with 'T')"
        })
        
        consistency_issues = False
        for check in consistency_checks:
            table_name = check["name"].split()[0].lower()
            if table_name not in table_counts:
                continue
                
            try:
                cursor.execute(check["sql"])
                count = cursor.fetchone()[0]
                if count > 0:
                    logger.error(f"Consistency issue: {count} {check['error_msg']}")
                    consistency_issues = True
                else:
                    logger.debug(f"Consistency check '{check['name']}': OK")
            except Exception as e:
                logger.error(f"Error running consistency check '{check['name']}': {e}")
                consistency_issues = True
        
        # 5. Check for duplicates
        duplicate_checks = [
            {
                "name": "Duplicate vulnerability entries",
                "sql": """
                    SELECT cve_id, COUNT(*) as count 
                    FROM vulnerabilities 
                    GROUP BY cve_id 
                    HAVING COUNT(*) > 1
                """,
                "error_msg": "duplicate vulnerability entries"
            },
            {
                "name": "Duplicate weakness entries",
                "sql": """
                    SELECT cwe_id, COUNT(*) as count 
                    FROM weaknesses 
                    GROUP BY cwe_id 
                    HAVING COUNT(*) > 1
                """,
                "error_msg": "duplicate weakness entries"
            },
            {
                "name": "Duplicate ATT&CK technique entries",
                "sql": """
                    SELECT technique_id, COUNT(*) as count 
                    FROM attack_techniques 
                    GROUP BY technique_id 
                    HAVING COUNT(*) > 1
                """,
                "error_msg": "duplicate ATT&CK technique entries"
            }
        ]
        
        duplicate_issues = False
        for check in duplicate_checks:
            table_name = check["name"].split()[1].lower()
            if table_name not in table_counts:
                continue
                
            try:
                cursor.execute(check["sql"])
                duplicates = cursor.fetchall()
                if duplicates:
                    logger.error(f"Found {len(duplicates)} {check['error_msg']}")
                    for dup in duplicates[:5]:  # Show only first 5 for brevity
                        logger.error(f"  {dup[0]}: {dup[1]} instances")
                    if len(duplicates) > 5:
                        logger.error(f"  ... and {len(duplicates) - 5} more")
                    duplicate_issues = True
                else:
                    logger.debug(f"Duplicate check '{check['name']}': OK")
            except Exception as e:
                logger.error(f"Error running duplicate check '{check['name']}': {e}")
                duplicate_issues = True
        
        # Summary
        issues_found = integrity_issues or quality_issues or consistency_issues or duplicate_issues
        
        if issues_found:
            logger.warning("Database verification completed with issues")
            return False
        else:
            logger.info("Database verification completed successfully")
            return True
            
    except Exception as e:
        logger.error(f"Error during database verification: {e}")
        return False
    finally:
        cursor.close()

        
def process_cve_data(db, raw_dir, processed_dir, force=False, min_year=2021):
    """
    Process CVE data from raw JSON files.
    
    Args:
        db: Database connection
        raw_dir: Directory containing raw CVE JSON files
        processed_dir: Directory to store processed data
        force: Whether to force reprocessing
        min_year: Minimum year to process CVEs from (default: 2021)
    
    Returns:
        list: Processed CVE records
    """
    # Check if processed data already exists
    processed_path = os.path.join(processed_dir, f"cve_data_parsed_from_{min_year}.json")
    if os.path.exists(processed_path) and not force:
        logger.info(f"Processed CVE data already exists at {processed_path}. Use --force to reprocess.")
        with open(processed_path, 'r', encoding='utf-8') as f:
            cve_data = json.load(f)
        logger.info(f"Loaded {len(cve_data)} processed CVE records from {min_year} onwards")
        return cve_data
    
    # Look for structured CVE directory (cves/YYYY/xxxx/CVE-YYYY-NNNNN.json)
    cve_dir = os.path.join(raw_dir, "cve_data", "cves")
    if os.path.exists(cve_dir):
        logger.info(f"Found structured CVE directory at {cve_dir}")
        try:
            # Import the dedicated parser for structured directories
            from data_processing.parse_cve_dir import parse_cve_directory
            
            # Parse CVEs using the dedicated parser with year filtering
            all_cve_records = parse_cve_directory(cve_dir, min_year)
            logger.info(f"Successfully parsed {len(all_cve_records)} CVE records from {min_year} onwards")
            
            # Save processed data
            os.makedirs(processed_dir, exist_ok=True)
            with open(processed_path, 'w', encoding='utf-8') as f:
                json.dump(all_cve_records, f, indent=2)
            
            logger.info(f"Saved processed CVE data to {processed_path}")
            return all_cve_records
        except Exception as e:
            logger.error(f"Error using structured CVE directory parser: {e}")
            logger.warning("Falling back to flat directory parser")
    
    # Fallback: Find CVE files to process in flat directory structure
    cve_flat_dir = os.path.join(raw_dir, "cve_data")
    cve_files = find_data_files(cve_flat_dir, "*.json")
    
    if not cve_files:
        logger.warning(f"No CVE files found in {cve_flat_dir}")
        return []
    
    logger.info(f"Found {len(cve_files)} CVE files to process using flat directory approach")
    
    # Process each CVE file
    all_cve_records = []
    for file_path in tqdm(cve_files, desc="Processing CVE files"):
        try:
            # Extract year from filename or path if possible
            year_match = re.search(r'CVE-(\d{4})-', file_path.name)
            if year_match:
                file_year = int(year_match.group(1))
                # Skip files older than min_year
                if file_year < min_year:
                    logger.debug(f"Skipping {file_path.name} - year {file_year} < min_year {min_year}")
                    continue
            
            with open(file_path, 'r', encoding='utf-8') as f:
                try:
                    cve_json = json.load(f)
                    
                    # Handle single record or multiple records format
                    if isinstance(cve_json, dict):
                        # Check CVE ID for year if available
                        if 'CVE_data_meta' in cve_json and 'ID' in cve_json['CVE_data_meta']:
                            cve_id = cve_json['CVE_data_meta']['ID']
                            year_match = re.search(r'CVE-(\d{4})-', cve_id)
                            if year_match and int(year_match.group(1)) < min_year:
                                continue
                        
                        parsed_record = parse_cve_record(cve_json)
                        all_cve_records.append(parsed_record)
                    elif isinstance(cve_json, list):
                        for record in cve_json:
                            # Check CVE ID for year if available
                            if 'CVE_data_meta' in record and 'ID' in record['CVE_data_meta']:
                                cve_id = record['CVE_data_meta']['ID']
                                year_match = re.search(r'CVE-(\d{4})-', cve_id)
                                if year_match and int(year_match.group(1)) < min_year:
                                    continue
                            
                            parsed_record = parse_cve_record(record)
                            all_cve_records.append(parsed_record)
                except json.JSONDecodeError:
                    logger.error(f"Error decoding JSON in {file_path}")
                    continue
        except Exception as e:
            logger.error(f"Error processing {file_path}: {e}")
    
    logger.info(f"Successfully parsed {len(all_cve_records)} CVE records from {min_year} onwards")
    
    # Save processed data
    os.makedirs(processed_dir, exist_ok=True)
    with open(processed_path, 'w', encoding='utf-8') as f:
        json.dump(all_cve_records, f, indent=2)
    
    logger.info(f"Saved processed CVE data to {processed_path}")
    return all_cve_records

def ensure_directories(base_dirs=None, raw_dirs=None):
    """Ensure all required directories exist."""
    if base_dirs is None:
        base_dirs = [
            "data",
            "analysis",
            "logs",
            "data_collection/processed_data",
        ]
    
    if raw_dirs is None:
        raw_dirs = [
            "data_collection/raw_data/cve_data",
            "data_collection/raw_data/nvd_data",
            "data_collection/raw_data/attack_data",
            "data_collection/raw_data/cwe_data",
            "data_collection/raw_data/capec_data",
            "data_collection/raw_data/mappings"
        ]
    
    for directory in base_dirs + raw_dirs:
        os.makedirs(directory, exist_ok=True)
        logger.debug(f"Ensured directory exists: {directory}")

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
    
    logger.info(f"Database schema exported to {output_path}")
    return True

def find_data_files(base_dir, pattern, recursive=True):
    """Find all files matching a pattern in a directory."""
    base_path = Path(base_dir)
    if recursive:
        return list(base_path.rglob(pattern))
    else:
        return list(base_path.glob(pattern))


def process_nvd_data(db, raw_dir, processed_dir, force=False):
    """
    Process NVD data from raw JSON files.
    
    Args:
        db: Database connection
        raw_dir: Directory containing raw NVD JSON files
        processed_dir: Directory to store processed data
        force: Whether to force reprocessing
    
    Returns:
        list: Processed NVD records
    """
    # Check if processed data already exists
    processed_path = os.path.join(processed_dir, "nvd_data_parsed.json")
    if os.path.exists(processed_path) and not force:
        logger.info(f"Processed NVD data already exists at {processed_path}. Use --force to reprocess.")
        with open(processed_path, 'r', encoding='utf-8') as f:
            nvd_data = json.load(f)
        logger.info(f"Loaded {len(nvd_data)} processed NVD records")
        return nvd_data
    
    # Find NVD files to process
    nvd_dir = os.path.join(raw_dir, "nvd_data")
    nvd_files = find_data_files(nvd_dir, "*.json")
    
    if not nvd_files:
        logger.warning(f"No NVD files found in {nvd_dir}")
        return []
    
    logger.info(f"Found {len(nvd_files)} NVD files to process")
    
    # Process each NVD file
    all_nvd_records = []
    for file_path in tqdm(nvd_files, desc="Processing NVD files"):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                try:
                    nvd_json = json.load(f)
                    
                    # Handle the standard NVD format with CVE_Items array
                    if "CVE_Items" in nvd_json:
                        for item in nvd_json["CVE_Items"]:
                            parsed_record = parse_nvd_record(item)
                            all_nvd_records.append(parsed_record)
                    elif isinstance(nvd_json, list):
                        # Handle cases where it's already a list of items
                        for item in nvd_json:
                            parsed_record = parse_nvd_record(item)
                            all_nvd_records.append(parsed_record)
                except json.JSONDecodeError:
                    logger.error(f"Error decoding JSON in {file_path}")
                    continue
        except Exception as e:
            logger.error(f"Error processing {file_path}: {e}")
    
    logger.info(f"Successfully parsed {len(all_nvd_records)} NVD records")
    
    # Save processed data
    os.makedirs(processed_dir, exist_ok=True)
    with open(processed_path, 'w', encoding='utf-8') as f:
        json.dump(all_nvd_records, f, indent=2)
    
    logger.info(f"Saved processed NVD data to {processed_path}")
    return all_nvd_records

def unify_vulnerability_data(cve_records, nvd_records, processed_dir):
    """
    Merge CVE and NVD data for the same vulnerabilities without losing data.
    
    Args:
        cve_records: Processed CVE records
        nvd_records: Processed NVD records
        processed_dir: Directory to store unified data
    
    Returns:
        list: Unified vulnerability records
    """
    logger.info("Unifying CVE and NVD data...")
    
    # Clean up NVD records - filter out error entries
    valid_nvd_records = []
    for record in nvd_records:
        # Check for error records (like those with "error_type" field only)
        if "error_type" in record and len(record.keys()) <= 2:
            logger.warning(f"Skipping invalid NVD record with error: {record.get('error_type', 'unknown')}")
            continue
        # Check if record has an ID (essential for unification)
        if not record.get("id"):
            logger.warning(f"Skipping NVD record without ID: {record}")
            continue
        
        valid_nvd_records.append(record)
    
    logger.info(f"Found {len(valid_nvd_records)} valid NVD records out of {len(nvd_records)}")
    
    # Create dictionary of valid NVD records by ID for faster lookup
    nvd_dict = {record["id"]: record for record in valid_nvd_records if "id" in record}
    
    unified_records = []
    
    # Process each CVE record
    errors = 0

    for cve_record in tqdm(cve_records, desc="Unifying records"):
        try:
            # Ensure CVE record has an ID
            if "id" not in cve_record:
                logger.warning(f"Skipping CVE record without ID: {cve_record}")
                continue
                
            cve_id = cve_record["id"]
            
            # Check if corresponding NVD record exists
            if cve_id in nvd_dict:
                nvd_record = nvd_dict[cve_id]
                
                # Helper function to safely get values with defaults
                def safe_get(record, field, default=None):
                    """Safely get a value from a record with a default if missing"""
                    if field not in record:
                        return default
                    if record[field] is None:
                        return default
                    return record[field]
                
                # Helper function to merge lists avoiding duplicates
                def safe_merge_lists(list1, list2):
                    """Merge two lists avoiding duplicates"""
                    if not list1 and not list2:
                        return []
                    if not list1:
                        return list2
                    if not list2:
                        return list1
                    
                    # Convert to sets to remove duplicates then back to list
                    # For complex items that aren't hashable, we need special handling
                    if isinstance(list1[0], dict) or isinstance(list2[0], dict):
                        # For lists of dictionaries (like products/references)
                        result = list(list1)  # Start with list1
                        # Only add items from list2 that aren't in list1
                        for item2 in list2:
                            if item2 not in result:
                                result.append(item2)
                        return result
                    else:
                        # For lists of simple types
                        return list(set(list1 + list2))
                
                # Helper function to merge nested dictionaries
                def deep_merge_dicts(dict1, dict2):
                    """Deeply merge two dictionaries without losing data"""
                    if not dict1:
                        return dict2 or {}
                    if not dict2:
                        return dict1 or {}
                    
                    result = dict1.copy()
                    for key, value in dict2.items():
                        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                            # Recursively merge nested dictionaries
                            result[key] = deep_merge_dicts(result[key], value)
                        elif key not in result or result[key] is None:
                            # Take value from dict2 if missing in dict1
                            result[key] = value
                        elif key in result and isinstance(result[key], list) and isinstance(value, list):
                            # Merge lists
                            result[key] = safe_merge_lists(result[key], value)
                        # Otherwise keep the value from dict1 (it has precedence)
                    return result
                
                # Merge the two records, preserving all data
                unified_record = {
                    "id": cve_id,
                    # Prefer NVD description if available, otherwise CVE
                    "description": safe_get(nvd_record, "description") or safe_get(cve_record, "description", ""),
                    
                    # Merge product lists, avoiding duplicates
                    "products": safe_merge_lists(
                        safe_get(nvd_record, "products", []), 
                        safe_get(cve_record, "products", [])
                    ),
                    
                    # Store the count for easier access
                    "product_count": max(
                        len(safe_get(nvd_record, "products", [])),
                        len(safe_get(cve_record, "products", []))
                    ),
                    
                    # Merge unique product names and vendors
                    "product_names": safe_merge_lists(
                        safe_get(nvd_record, "product_names", []),
                        safe_get(cve_record, "product_names", [])
                    ),
                    
                    "vendors": safe_merge_lists(
                        safe_get(nvd_record, "vendors", []),
                        safe_get(cve_record, "vendors", [])
                    ),
                    
                    # Merge CWE, CAPEC, and ATT&CK information
                    "cwe": safe_merge_lists(
                        safe_get(nvd_record, "cwe", []), 
                        safe_get(cve_record, "cwe", [])
                    ),
                    
                    "cwe_inferred": safe_get(nvd_record, "cwe_inferred", False) or safe_get(cve_record, "cwe_inferred", False),
                    
                    "capec": safe_merge_lists(
                        safe_get(nvd_record, "capec", []), 
                        safe_get(cve_record, "capec", [])
                    ),
                    
                    "attack_technique": safe_merge_lists(
                        safe_get(nvd_record, "attack_technique", []), 
                        safe_get(cve_record, "attack_technique", [])
                    ),
                    
                    # Prefer NVD CVSS data, fall back to CVE
                    "cvss": safe_get(nvd_record, "cvss", {}) or safe_get(cve_record, "cvss", {}),
                    
                    # Extract key metrics for easier access
                    "base_score": safe_get(nvd_record, "base_score") or safe_get(cve_record, "base_score", 0),
                    "exploitability_score": safe_get(nvd_record, "exploitability_score") or safe_get(cve_record, "exploitability_score", 0),
                    "impact_score": safe_get(nvd_record, "impact_score") or safe_get(cve_record, "impact_score", 0),
                    "severity": safe_get(nvd_record, "severity") or safe_get(cve_record, "severity", ""),
                    
                    # Merge reference information
                    "references": safe_merge_lists(
                        safe_get(nvd_record, "references", []), 
                        safe_get(cve_record, "references", [])
                    ),
                    
                    "reference_count": max(
                        len(safe_get(nvd_record, "references", [])),
                        len(safe_get(cve_record, "references", []))
                    ),
                    
                    "reference_details": safe_merge_lists(
                        safe_get(nvd_record, "reference_details", []), 
                        safe_get(cve_record, "reference_details", [])
                    ),
                    
                    "exploit_references": safe_merge_lists(
                        safe_get(nvd_record, "exploit_references", []), 
                        safe_get(cve_record, "exploit_references", [])
                    ),
                    
                    # Prefer CVE reporter if available
                    "reporter": safe_get(cve_record, "reporter") or safe_get(nvd_record, "reporter", ""),
                    
                    # Combine exploit information (prefer "yes" over "no")
                    "known_exploited": safe_get(nvd_record, "known_exploited", False) or safe_get(cve_record, "known_exploited", False),
                    "has_exploit": safe_get(nvd_record, "has_exploit", False) or safe_get(cve_record, "has_exploit", False),
                    "has_cisa_advisory": safe_get(nvd_record, "has_cisa_advisory", False) or safe_get(cve_record, "has_cisa_advisory", False),
                    "has_vendor_advisory": safe_get(nvd_record, "has_vendor_advisory", False) or safe_get(cve_record, "has_vendor_advisory", False),
                    "exploit_available": safe_get(nvd_record, "exploit_available", False) or safe_get(cve_record, "exploit_available", False),
                    "exploit_maturity": max(
                        safe_get(nvd_record, "exploit_maturity", 1),
                        safe_get(cve_record, "exploit_maturity", 1)
                    ),
                    
                    # Prefer the earliest published date and latest modified date
                    "published": min(
                        safe_get(nvd_record, "published", "9999-12-31"),
                        safe_get(cve_record, "published", "9999-12-31")
                    ) if (safe_get(nvd_record, "published") or safe_get(cve_record, "published")) else None,
                    
                    "modified": max(
                        safe_get(nvd_record, "modified", "1970-01-01"),
                        safe_get(cve_record, "modified", "1970-01-01")
                    ) if (safe_get(nvd_record, "modified") or safe_get(cve_record, "modified")) else None,
                    
                    # Keep redundant date fields for backward compatibility
                    "published_date": min(
                        safe_get(nvd_record, "published_date", "9999-12-31"),
                        safe_get(cve_record, "published_date", "9999-12-31")
                    ) if (safe_get(nvd_record, "published_date") or safe_get(cve_record, "published_date")) else None,
                    
                    "modified_date": max(
                        safe_get(nvd_record, "modified_date", "1970-01-01"),
                        safe_get(cve_record, "modified_date", "1970-01-01")
                    ) if (safe_get(nvd_record, "modified_date") or safe_get(cve_record, "modified_date")) else None,
                    
                    # Take highest EPSS score available
                    "epss_score": max(
                        safe_get(nvd_record, "epss_score", 0) or 0,
                        safe_get(cve_record, "epss_score", 0) or 0
                    ) or None,  # Convert 0 to None if both were None
                    
                    "epss_percentile": max(
                        safe_get(nvd_record, "epss_percentile", 0) or 0,
                        safe_get(cve_record, "epss_percentile", 0) or 0
                    ) or None,  # Convert 0 to None if both were None
                    
                    # Merge CISA fields
                    "cisa_fields": deep_merge_dicts(
                        safe_get(cve_record, "cisa_fields", {}),
                        safe_get(nvd_record, "cisa_fields", {})
                    ),
                    
                    # Merge vulnrichment data from both sources
                    "vulnrichment": deep_merge_dicts(
                        safe_get(cve_record, "vulnrichment", {}),
                        safe_get(nvd_record, "vulnrichment", {})
                    ),
                    
                    # Preserve original source information
                    "other": {
                        "source": "unified_cve_nvd",
                        "cve_source": safe_get(cve_record, "other", {}).get("source"),
                        "nvd_source": safe_get(nvd_record, "other", {}).get("source"),
                        "published": safe_get(cve_record, "other", {}).get("published") or safe_get(nvd_record, "other", {}).get("published"),
                        "modified": safe_get(cve_record, "other", {}).get("modified") or safe_get(nvd_record, "other", {}).get("modified"),
                        "year": safe_get(cve_record, "other", {}).get("year") or safe_get(nvd_record, "other", {}).get("year"),
                        # Preserve any other fields from both sources
                        **{k: v for k, v in safe_get(cve_record, "other", {}).items() if k not in ["source", "published", "modified", "year"]},
                        **{k: v for k, v in safe_get(nvd_record, "other", {}).items() if k not in ["source", "published", "modified", "year"]}
                    }
                }
                
                unified_records.append(unified_record)
                
                # Remove from NVD dict to track which ones were processed
                del nvd_dict[cve_id]
            else:
                # No corresponding NVD record, just use the CVE record
                # Ensure 'other' field exists
                if "other" not in cve_record:
                    cve_record["other"] = {}
                cve_record["other"]["source"] = "cve_only"
                unified_records.append(cve_record)
        except Exception as e:
            errors += 1
            logger.error(f"Error unifying record ({errors}) {cve_record.get('id', 'unknown')}: {e}")
            continue
    
    # Add remaining NVD records that don't have CVE counterparts
    for nvd_id, nvd_record in nvd_dict.items():
        try:
            # Ensure 'other' field exists
            if "other" not in nvd_record:
                nvd_record["other"] = {}
            nvd_record["other"]["source"] = "nvd_only"
            unified_records.append(nvd_record)
        except Exception as e:
            logger.error(f"Error adding NVD-only record {nvd_id}: {e}")
            continue
    
    logger.info(f"Created {len(unified_records)} unified vulnerability records")
    logger.info(f"Encountered {errors} errors during unification")
    
    # Save unified data
    unified_path = os.path.join(processed_dir, "unified_vulns.json")
    with open(unified_path, 'w', encoding='utf-8') as f:
        json.dump(unified_records, f, indent=2)
    
    logger.info(f"Saved unified vulnerability data to {unified_path}")
    return unified_records


def populate_cwe_data(db, raw_dir, processed_dir, force=False):
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
        logger.info(f"CWE data already exists ({cwe_count} records). Use --force to update.")
        return False
    
    # Find the CWE XML file
    cwe_dir = os.path.join(raw_dir, "cwe_data")
    cwe_files = find_data_files(cwe_dir, "cwec*.xml")
    
    if not cwe_files:
        logger.warning(f"No CWE XML files found in {cwe_dir}")
        return False
    
    # Use the most recent CWE file (assuming filenames contain version)
    cwe_xml_path = str(sorted(cwe_files)[-1])
    
    # Parse the CWE XML file
    logger.info(f"Parsing CWE data from {cwe_xml_path}...")
    cwe_entries = parse_cwe_xml(cwe_xml_path)
    
    if not cwe_entries:
        logger.error("No CWE entries found in the XML file.")
        return False
    
    logger.info(f"Inserting {len(cwe_entries)} CWE entries into database...")
    success_count = 0
    for entry in tqdm(cwe_entries, desc="Inserting CWE entries"):
        try:
            if db.insert_cwe(entry):
                success_count += 1
        except Exception as e:
            logger.error(f"Error inserting CWE {entry.get('cwe_id')}: {e}")
    
    logger.info(f"Successfully inserted/updated {success_count} of {len(cwe_entries)} CWE entries")
    
    # Export CWE mappings to analysis directory
    export_cwe_mappings(db, os.path.join(processed_dir, ".."))
    
    return True

def export_cwe_mappings(db, output_dir="analysis"):
    """Export CWE mappings to JSON and CSV formats."""
    conn = db.connect()
    
    # Use PostgreSQL syntax directly, no need to check
    query = """
    SELECT 
        cwe_id, 
        name, 
        description, 
        extended_description, 
        abstraction, 
        status, 
        category, 
        likelihood,
        mitigations_text as mitigations
    FROM weaknesses
    ORDER BY cwe_id
    """
    
    df = pd.read_sql_query(query, conn)
    
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Export to JSON and CSV
    json_path = os.path.join(output_dir, "analysis", "cwe_mappings.json")
    os.makedirs(os.path.dirname(json_path), exist_ok=True)
    df.to_json(json_path, orient='records', indent=2)
    
    csv_path = os.path.join(output_dir, "analysis", "cwe_mappings.csv")
    os.makedirs(os.path.dirname(csv_path), exist_ok=True)
    df.to_csv(csv_path, index=False)
    
    # Also create a CAPEC-CWE mapping file
    try:
        from data_processing.mappers.cwe_capec_mapper import load_cwe_capec_mapping, generate_cwe_capec_mapping
        
        # Check if we need to generate the mapping first
        capec_mapping = load_cwe_capec_mapping()
        if not capec_mapping:
            logger.info("Generating CWE-CAPEC mapping...")
            generate_cwe_capec_mapping(db, os.path.join(output_dir, "data_collection", "processed_data"))
    except Exception as e:
        logger.warning(f"Error generating CWE-CAPEC mapping: {e}")
    
    logger.info(f"CWE mappings exported to {json_path} and {csv_path}")
    return df
def process_attack_data(db, raw_dir, force=False):
    """Process and load ATT&CK data if it doesn't exist or if force update is requested."""
    # Check if ATT&CK data already exists
    conn = db.connect()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM attack_techniques")
    technique_count = cursor.fetchone()[0]
    
    if technique_count > 0 and not force:
        logger.info(f"ATT&CK data already exists ({technique_count} techniques). Use --force to update.")
        return False
    
    # Search for the ATT&CK data file
    attack_dir = os.path.join(raw_dir, "attack_data")
    attack_files = find_data_files(attack_dir, "enterprise-attack*.json")
    
    if not attack_files:
        logger.warning(f"No ATT&CK data files found in {attack_dir}")
        return False
    
    # Use the most recent ATT&CK file
    attack_file = str(sorted(attack_files)[-1])
    
    # Parse ATT&CK data
    logger.info(f"Parsing ATT&CK data from {attack_file}...")
    techniques = parse_attack_data(attack_file)
    
    if not techniques:
        logger.error("No techniques found in the ATT&CK data file.")
        return False
    
    logger.info(f"Inserting {len(techniques)} ATT&CK techniques into database...")
    inserted = 0
    
    # Insert each technique
    for technique in tqdm(techniques, desc="Inserting ATT&CK techniques"):
        try:
            db.insert_attack_technique(technique)
            inserted += 1
        except Exception as e:
            logger.error(f"Error inserting technique {technique.get('technique_id')}: {e}")
    
    logger.info(f"Successfully inserted {inserted} of {len(techniques)} ATT&CK techniques")
    return True

def process_capec_data(db, raw_dir, force=False):
    """Process and load CAPEC data if it doesn't exist or if force update is requested."""
    # Directory and file paths
    capec_dir = os.path.join(raw_dir, "capec_data")
    capec_json_path = os.path.join(capec_dir, "capec_v3.9.json")
    
    # Skip if CAPEC data already exists and not forced
    if os.path.exists(capec_json_path) and not force:
        logger.info(f"CAPEC data already exists at {capec_json_path}. Use --force to update.")
        return True
    
    # Check for CAPEC XML file
    capec_xml_files = find_data_files(capec_dir, "capec_v*.xml")
    
    if not capec_xml_files:
        logger.warning(f"No CAPEC XML files found in {capec_dir}. Need to download CAPEC XML.")
        # You might want to add download code here or instruct the user to download it
        logger.info(f"Please download the latest CAPEC XML from https://capec.mitre.org/data/xml/capec_latest.xml")
        logger.info(f"and save it to {capec_dir}")
        return False
    
    # Use the most recent CAPEC file
    capec_xml_path = str(sorted(capec_xml_files)[-1])
    logger.info(f"Parsing CAPEC data from {capec_xml_path}...")
    
    try:
        # Parse the CAPEC XML file
        from data_processing.parse_capec import parse_capec_xml
        capec_data = parse_capec_xml(capec_xml_path)
        
        if not capec_data:
            logger.error("No CAPEC entries found in the XML file.")
            return False
        
        # Save processed data to JSON
        os.makedirs(os.path.dirname(capec_json_path), exist_ok=True)
        with open(capec_json_path, 'w', encoding='utf-8') as f:
            json.dump(capec_data, f, indent=2)
            
        logger.info(f"Successfully processed {len(capec_data.get('attack_patterns', []))} CAPEC entries")
        logger.info(f"Saved processed CAPEC data to {capec_json_path}")
        
        return True
    except Exception as e:
        logger.error(f"Error processing CAPEC data: {e}")
        return False
    
def create_attack_mappings(db, force=False):
    """Create vulnerability-to-ATT&CK mappings if they don't exist or if force update is requested."""
    conn = db.connect()
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT COUNT(*) FROM vulnerability_attack_mappings")
        mapping_count = cursor.fetchone()[0]
        
        if mapping_count > 0 and not force:
            logger.info(f"Vulnerability-to-ATT&CK mappings already exist ({mapping_count} mappings). Use --force to update.")
            return True
        
        # Check if we have the prerequisites
        cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
        vuln_count = cursor.fetchone()[0]
        logger.info(f"Found {vuln_count} vulnerabilities for potential ATT&CK mapping")
        
        cursor.execute("SELECT COUNT(*) FROM attack_techniques")
        technique_count = cursor.fetchone()[0]
        logger.info(f"Found {technique_count} ATT&CK techniques for mapping")
        
        cursor.execute("SELECT COUNT(*) FROM vulnerability_weaknesses")
        vuln_cwe_count = cursor.fetchone()[0]
        logger.info(f"Found {vuln_cwe_count} vulnerability-to-CWE mappings")
        
        if vuln_count == 0:
            logger.error("No vulnerabilities found in the database. Mappings can't be created.")
            return False
        
        if technique_count == 0:
            logger.error("No ATT&CK techniques found in the database. Mappings can't be created.")
            return False
            
        if vuln_cwe_count == 0:
            logger.warning("No vulnerability-to-CWE mappings found. Creating ATT&CK mappings will be limited.")
        
        # Delete existing mappings if force is True
        if force and mapping_count > 0:
            logger.info(f"Deleting {mapping_count} existing mappings...")
            cursor.execute("DELETE FROM vulnerability_attack_mappings")
            conn.commit()
        
        # STEP 1: Map vulnerabilities with CWEs to ATT&CK via CWE-CAPEC relationship
        logger.info("Step 1: Mapping vulnerabilities to ATT&CK via CWE-CAPEC relationships...")
        
        # Get all vulnerabilities with CWEs
        cursor.execute("""
            SELECT v.id, vw.cwe_id 
            FROM vulnerabilities v
            JOIN vulnerability_weaknesses vw ON v.id = vw.vuln_id
                       
        """)
        vuln_cwe_pairs = cursor.fetchall()
        
        if vuln_cwe_pairs:
            logger.info(f"Found {len(vuln_cwe_pairs)} vulnerability-CWE associations")
            
            # Load CWE-CAPEC mapping
            from data_processing.mappers.cwe_capec_mapper import load_cwe_capec_mapping
            cwe_capec_mapping = load_cwe_capec_mapping()
            
            if not cwe_capec_mapping:
                logger.warning("No CWE-CAPEC mappings available. Trying alternative mapping approach.")
            else:
                logger.info(f"Loaded CWE-CAPEC mapping with {len(cwe_capec_mapping)} entries")
                
                # Get all ATT&CK techniques for mapping
                cursor.execute("SELECT technique_id, name FROM attack_techniques")
                techniques = cursor.fetchall()
                technique_ids = [t[0] for t in techniques]
                technique_names = {t[0]: t[1].lower() for t in techniques}
                
                # Create a CAPEC-to-ATT&CK mapping based on keywords and patterns
                # This is a more sophisticated approach than simple modulo assignment
                capec_attack_mapping = {}
                
                # Define ATT&CK technique categories for mapping
                technique_categories = {
                    'execution': ['T1059', 'T1203', 'T1106'],
                    'privilege_escalation': ['T1068', 'T1134', 'T1484'],
                    'defense_evasion': ['T1562', 'T1070', 'T1027'],
                    'credential_access': ['T1110', 'T1212', 'T1003'],
                    'discovery': ['T1046', 'T1087', 'T1082'],
                    'lateral_movement': ['T1021', 'T1091', 'T1210'],
                    'collection': ['T1560', 'T1113', 'T1114'],
                    'exfiltration': ['T1048', 'T1567', 'T1041'],
                    'initial_access': ['T1190', 'T1566', 'T1133'],
                }
                
                # CWE to ATT&CK technique category mappings
                cwe_category_mappings = {
                    # Web vulnerabilities
                    'CWE-79': 'execution',  # XSS
                    'CWE-89': 'execution',  # SQL Injection
                    'CWE-78': 'execution',  # Command Injection
                    'CWE-94': 'execution',  # Code Injection
                    
                    # Access control
                    'CWE-285': 'privilege_escalation',  # Authorization
                    'CWE-287': 'credential_access',  # Authentication
                    'CWE-306': 'credential_access',  # Missing Auth
                    
                    # Memory safety
                    'CWE-119': 'execution',  # Buffer overflow
                    'CWE-120': 'execution',  # Buffer overflow
                    'CWE-416': 'execution',  # Use after free
                    
                    # Information disclosure
                    'CWE-200': 'discovery',  # Info disclosure
                    'CWE-209': 'discovery',  # Error info leakage
                    
                    # Cryptography
                    'CWE-327': 'defense_evasion',  # Broken crypto
                    'CWE-326': 'defense_evasion',  # Insufficient crypto
                    
                    # Web specific
                    'CWE-352': 'privilege_escalation',  # CSRF
                    'CWE-434': 'initial_access',  # File upload
                    
                    # Network
                    'CWE-400': 'initial_access',  # Resource exhaustion
                    'CWE-601': 'initial_access',  # Open redirect
                }
                
                # Create mappings based on these relationships
                new_mapping_count = 0
                for vuln_id, cwe_id in tqdm(vuln_cwe_pairs, desc="Creating ATT&CK mappings via CWE"):
                    try:
                        # Get category for this CWE
                        category = cwe_category_mappings.get(cwe_id)
                        
                        # If we have a category mapping, use it
                        if category:
                            # Select techniques from this category
                            potential_techniques = technique_categories.get(category, [])
                            
                            if potential_techniques:
                                # Use the first technique as a simple mapping
                                technique_id = potential_techniques[0]
                                
                                # Insert the mapping
                                if isinstance(db, VulnerabilityDatabase):  # SQLite
                                    cursor.execute("""
                                        INSERT OR IGNORE INTO vulnerability_attack_mappings 
                                        (vuln_id, technique_id, confidence, source) 
                                        VALUES (?, ?, ?, ?)
                                    """, (vuln_id, technique_id, 0.7, "cwe_category_mapping"))
                                else:  # PostgreSQL
                                    cursor.execute("""
                                        INSERT INTO vulnerability_attack_mappings 
                                        (vuln_id, technique_id, confidence, source) 
                                        VALUES (%s, %s, %s, %s)
                                        ON CONFLICT (vuln_id, technique_id) DO NOTHING
                                    """, (vuln_id, technique_id, 0.7, "cwe_category_mapping"))
                                    
                                new_mapping_count += 1
                            
                        # Also try CAPEC mapping as fallback
                        capec_ids = cwe_capec_mapping.get(cwe_id, [])
                        if not isinstance(capec_ids, list):
                            capec_ids = [capec_ids]
                        
                        for capec_id in capec_ids:
                            # Simple deterministic mapping based on CAPEC ID number
                            capec_num = capec_id.replace("CAPEC-", "")
                            if capec_num.isdigit():
                                # Map CAPEC to a specific ATT&CK technique 
                                technique_idx = int(capec_num) % len(technique_ids)
                                technique_id = technique_ids[technique_idx]
                                
                                # Insert mapping
                                if isinstance(db, VulnerabilityDatabase):  # SQLite
                                    cursor.execute("""
                                        INSERT OR IGNORE INTO vulnerability_attack_mappings 
                                        (vuln_id, technique_id, confidence, source) 
                                        VALUES (?, ?, ?, ?)
                                    """, (vuln_id, technique_id, 0.6, "capec_mapping"))
                                else:  # PostgreSQL
                                    cursor.execute("""
                                        INSERT INTO vulnerability_attack_mappings 
                                        (vuln_id, technique_id, confidence, source) 
                                        VALUES (%s, %s, %s, %s)
                                        ON CONFLICT (vuln_id, technique_id) DO NOTHING
                                    """, (vuln_id, technique_id, 0.6, "capec_mapping"))
                                    
                                new_mapping_count += 1
                            
                        # Commit periodically
                        if new_mapping_count % 1000 == 0:
                            conn.commit()
                            logger.info(f"Created {new_mapping_count} ATT&CK mappings so far...")
                            
                    except Exception as e:
                        logger.error(f"Error mapping vulnerability {vuln_id} to ATT&CK: {e}")
                
                # Commit any remaining changes
                conn.commit()
        
        # STEP 2: For vulnerabilities without CWE mappings, try direct mapping from descriptions
        logger.info("Step 2: Mapping vulnerabilities to ATT&CK based on descriptions...")
        
        # Get vulnerabilities without ATT&CK mappings
        cursor.execute("""
            SELECT v.id, v.description 
            FROM vulnerabilities v
            LEFT JOIN vulnerability_attack_mappings vam ON v.id = vam.vuln_id
            WHERE vam.vuln_id IS NULL AND v.description IS NOT NULL AND v.description != ''
            LIMIT 5000  -- Limit to avoid processing too many
        """)
        unmapped_vulns = cursor.fetchall()
        
        if unmapped_vulns:
            logger.info(f"Found {len(unmapped_vulns)} unmapped vulnerabilities with descriptions")
            
            # Get all technique names for keyword matching
            cursor.execute("SELECT technique_id, name FROM attack_techniques")
            techniques = cursor.fetchall()
            technique_names = {t[0]: t[1].lower() for t in techniques}
            
            # Simple keyword to ATT&CK technique mapping
            keyword_mappings = {
                'sql injection': 'T1190',  # Exploit Public-Facing Application
                'cross site': 'T1059',     # Command and Scripting Interpreter
                'xss': 'T1059',           # Command and Scripting Interpreter
                'command injection': 'T1059', # Command and Scripting Interpreter
                'buffer overflow': 'T1203', # Exploitation for Client Execution
                'authentication bypass': 'T1212', # Exploitation for Credential Access
                'privilege escalation': 'T1068', # Exploitation for Privilege Escalation
                'denial of service': 'T1499', # Endpoint Denial of Service
                'information disclosure': 'T1082', # System Information Discovery
                'remote code execution': 'T1059', # Command and Scripting Interpreter
                'path traversal': 'T1083', # File and Directory Discovery
                'directory traversal': 'T1083', # File and Directory Discovery
                'file inclusion': 'T1203', # Exploitation for Client Execution
                'csrf': 'T1204',  # User Execution
                'clickjacking': 'T1204', # User Execution
                'weak password': 'T1110', # Brute Force
                'default credential': 'T1110', # Brute Force
                'hardcoded credential': 'T1552', # Unsecured Credentials
                'information leak': 'T1082', # System Information Discovery
                'memory corruption': 'T1203' # Exploitation for Client Execution
            }
            
            # Count direct mappings made
            direct_mappings = 0
            
            for vuln_id, description in tqdm(unmapped_vulns, desc="Mapping vulnerabilities by description"):
                if not description:
                    continue
                    
                description_lower = description.lower()
                mapped = False
                
                # Try keyword mapping
                for keyword, technique_id in keyword_mappings.items():
                    if keyword in description_lower:
                        # Insert mapping with lower confidence since it's keyword-based
                        if isinstance(db, VulnerabilityDatabase):  # SQLite
                            cursor.execute("""
                                INSERT OR IGNORE INTO vulnerability_attack_mappings 
                                (vuln_id, technique_id, confidence, source) 
                                VALUES (?, ?, ?, ?)
                            """, (vuln_id, technique_id, 0.5, "keyword_mapping"))
                        else:  # PostgreSQL
                            cursor.execute("""
                                INSERT INTO vulnerability_attack_mappings 
                                (vuln_id, technique_id, confidence, source) 
                                VALUES (%s, %s, %s, %s)
                                ON CONFLICT (vuln_id, technique_id) DO NOTHING
                            """, (vuln_id, technique_id, 0.5, "keyword_mapping"))
                            
                        direct_mappings += 1
                        mapped = True
                        break
                
                # Only commit occasionally to minimize overhead
                if direct_mappings % 500 == 0 and direct_mappings > 0:
                    conn.commit()
            
            # Commit any remaining changes
            conn.commit()
            logger.info(f"Created {direct_mappings} direct keyword mappings")
        
        # Check final mapping count
        cursor.execute("SELECT COUNT(*) FROM vulnerability_attack_mappings")
        final_count = cursor.fetchone()[0]
        new_mappings = final_count - mapping_count
        
        logger.info(f"ATT&CK mapping complete. Created {new_mappings} new mappings.")
        return True
        
    except Exception as e:
        logger.error(f"Error creating vulnerability-to-ATT&CK mappings: {e}")
        conn.rollback()
        return False
    finally:
        cursor.close()

def create_vulnerability_cwe_mappings(db, force=False):
    """Create vulnerability-to-CWE mappings based on parsed CVE data."""
    is_postgres = hasattr(db.connect(), 'server_version')
    conn = db.connect()
    cursor = conn.cursor()
    
    try:
        logger.info("Creating vulnerability-to-CWE mappings...")
        
        # Check if mappings already exist
        cursor.execute("SELECT COUNT(*) FROM vulnerability_weaknesses")
        existing_count = cursor.fetchone()[0]
        
        if existing_count > 0 and not force:
            logger.info(f"Found {existing_count} existing mappings. Use --force to recreate.")
            return True
            
        if force and existing_count > 0:
            logger.info(f"Removing {existing_count} existing mappings...")
            cursor.execute("DELETE FROM vulnerability_weaknesses")
            conn.commit()
        
        # Get all vulnerabilities with CWE data
        placeholder = "%s" if is_postgres else "?"
        query = f"SELECT id, data FROM vulnerabilities WHERE data::jsonb ? 'cwe'"
        
        if not is_postgres:
            # For SQLite, we need a different approach
            query = "SELECT id, data FROM vulnerabilities WHERE json_extract(data, '$.cwe') IS NOT NULL"
            
        cursor.execute(query)
        vulns = cursor.fetchall()
        logger.info(f"Found {len(vulns)} vulnerabilities with CWE field")
        
        mapping_count = 0
        for vuln_id, data in tqdm(vulns, desc="Creating CWE mappings"):
            # Parse data if it's a string
            if isinstance(data, str):
                try:
                    vuln_data = json.loads(data)
                except json.JSONDecodeError:
                    logger.warning(f"Invalid JSON for vulnerability {vuln_id}")
                    continue
            else:
                vuln_data = data
                
            # Extract CWEs
            cwes = vuln_data.get('cwe', [])
            if not cwes:
                continue
                
            # Ensure cwes is a list
            if not isinstance(cwes, list):
                cwes = [cwes]
                
            # Create mappings for each CWE
            for cwe_id in cwes:
                if not isinstance(cwe_id, str) or not cwe_id.startswith("CWE-"):
                    # Skip invalid CWE IDs
                    logger.debug(f"Skipping invalid CWE: {cwe_id}")
                    continue
                    
                # Insert mapping
                try:
                    if is_postgres:
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
                        
                    mapping_count += 1
                    
                except Exception as e:
                    logger.error(f"Error mapping {vuln_id} to {cwe_id}: {e}")
                    if is_postgres:
                        # Rollback on error to avoid transaction aborted state
                        conn.rollback()
            
            # Commit periodically
            if mapping_count % 5000 == 0:
                conn.commit()
                logger.info(f"Created {mapping_count} CWE mappings...")
        
        # Final commit
        conn.commit()
        logger.info(f"Successfully created {mapping_count} vulnerability-to-CWE mappings")
        return True
        
    except Exception as e:
        logger.error(f"Error creating vulnerability-to-CWE mappings: {e}")
        conn.rollback()
        return False
    finally:
        cursor.close()

def export_classification_data(db):
    """
    Export vulnerability data for classification and analysis with improved field handling.
    This is a key part of TWX's goal to unbias vulnerability data through proper classification.
    
    Args:
        db: Database connection
        
    Returns:
        DataFrame: Pandas DataFrame with classification data
    """
    # Create a fresh connection to avoid transaction issues
    conn = db.connect()
    if hasattr(conn, 'status') and conn.status == psycopg2.extensions.STATUS_IN_TRANSACTION:
        conn.rollback()  # Clear any failed transaction
    
    # Check if we're using PostgreSQL or SQLite
    is_postgres = hasattr(conn, 'server_version')
    
    try:
        logger.info("Exporting classification data from database...")
        
        if is_postgres:
            # Use the dedicated PostgreSQL export function for better performance
            return db.export_to_json("analysis/classification_data.json")
        else:
            # For SQLite, use the specific implementation below
            # SQLite query implementation (omitted for brevity)
            pass
            
    except Exception as e:
        logger.error(f"Error in classification data export: {e}")
        # Try fallback method if primary fails
        try:
            logger.info("Attempting fallback export method...")
            
            # Simple query that works on both PostgreSQL and SQLite
            basic_query = """
            SELECT 
                id as vuln_id,
                description,
                published,
                modified,
                reporter,
                source,
                known_exploited,
                has_exploit,
                base_score,
                severity,
                cvss_version,
                cvss_vector,
                exploitability_score,
                impact_score,
                attack_vector,
                attack_complexity,
                privileges_required,
                user_interaction,
                primary_cwe,
                vuln_type,
                product_count,
                reference_count,
                epss_score,
                epss_percentile
            FROM vulnerabilities
            ORDER BY published DESC
            """
            
            df = pd.read_sql_query(basic_query, conn)
            

            date_cols = ['published', 'modified']
            for col in date_cols:
                if col in df.columns and df[col].notnull().any():
                    df[col] = pd.to_datetime(df[col], errors='coerce', utc=True)
                    # Format dates consistently
                    df[col] = df[col].dt.strftime('%Y-%m-%d %H:%M:%S')
            # Save fallback data
            output_path = "analysis/classification_data.csv"
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            df.to_csv(output_path, index=False)
            
            # Export sample for inspection
            sample_path = "analysis/classification_sample.csv"
            df.head(50).to_csv(sample_path, index=False)
            
            logger.info(f"Exported fallback classification data for {len(df)} vulnerabilities")
            return df
            
        except Exception as e2:
            logger.error(f"Fallback export also failed: {e2}")
            return pd.DataFrame() 
        
def extract_cwe_categories(cwe_entries):
    """
    Organize CWEs by category to support classification.
    
    Args:
        cwe_entries: List of parsed CWE entries
        
    Returns:
        Dictionary mapping categories to information about that category
    """
    import re
    
    # Create structured categories
    categories = {
        "Memory Safety": {
            "description": "Vulnerabilities related to memory management and access",
            "cwe_ids": [],
            "subcategories": {
                "Buffer Overflows": [],
                "Memory Leaks": [],
                "Use After Free": [],
                "Double Free": [],
                "Null Pointer Dereference": []
            }
        },
        "Injection": {
            "description": "Vulnerabilities allowing code or data injection",
            "cwe_ids": [],
            "subcategories": {
                "SQL Injection": [],
                "Command Injection": [],
                "Cross-site Scripting": [],
                "LDAP Injection": [],
                "XML Injection": [],
                "Format String": []
            }
        },
        "Access Control": {
            "description": "Vulnerabilities affecting authorization and permissions",
            "cwe_ids": [],
            "subcategories": {
                "Missing Authorization": [],
                "Broken Authentication": [],
                "Path Traversal": [],
                "Privilege Escalation": [],
                "Incorrect Permissions": []
            }
        },
        "Cryptographic Issues": {
            "description": "Vulnerabilities in cryptographic implementation or usage",
            "cwe_ids": [],
            "subcategories": {
                "Weak Encryption": [],
                "Insufficient Entropy": [],
                "Broken Algorithms": [],
                "Key Management": [],
                "Certificate Validation": []
            }
        },
        "Information Disclosure": {
            "description": "Vulnerabilities leading to unauthorized data exposure",
            "cwe_ids": [],
            "subcategories": {
                "Sensitive Data Exposure": [],
                "Information Leakage": [],
                "Debug Information": [],
                "Error Messages": []
            }
        },
        "Input Validation": {
            "description": "Vulnerabilities due to insufficient input handling",
            "cwe_ids": [],
            "subcategories": {
                "Missing Validation": [],
                "Incorrect Input Handling": [],
                "Type Confusion": []
            }
        },
        "Resource Management": {
            "description": "Vulnerabilities in managing system resources",
            "cwe_ids": [],
            "subcategories": {
                "Race Conditions": [],
                "Deadlocks": [],
                "Denial of Service": [],
                "Uncontrolled Resource Consumption": []
            }
        },
        "Insecure Design": {
            "description": "Vulnerabilities due to flawed design rather than implementation",
            "cwe_ids": [],
            "subcategories": {
                "Missing Security Controls": [],
                "Unsafe Defaults": [],
                "Trust Boundary Violations": []
            }
        },
        "Time and State": {
            "description": "Vulnerabilities related to timing and state management",
            "cwe_ids": [],
            "subcategories": {
                "TOCTOU": [],
                "Session Management": [],
                "Race Conditions": []
            }
        }
    }
    
    # Specific CWE mappings to categories and subcategories
    specific_mappings = {
        # Memory Safety
        "CWE-119": ("Memory Safety", "Buffer Overflows"),
        "CWE-120": ("Memory Safety", "Buffer Overflows"),
        "CWE-122": ("Memory Safety", "Buffer Overflows"),
        "CWE-125": ("Memory Safety", "Buffer Overflows"),
        "CWE-787": ("Memory Safety", "Buffer Overflows"),
        "CWE-416": ("Memory Safety", "Use After Free"),
        "CWE-415": ("Memory Safety", "Double Free"),
        "CWE-476": ("Memory Safety", "Null Pointer Dereference"),
        
        # Injection
        "CWE-89": ("Injection", "SQL Injection"),
        "CWE-564": ("Injection", "SQL Injection"),
        "CWE-77": ("Injection", "Command Injection"),
        "CWE-78": ("Injection", "Command Injection"),
        "CWE-79": ("Injection", "Cross-site Scripting"),
        "CWE-80": ("Injection", "Cross-site Scripting"),
        "CWE-83": ("Injection", "Cross-site Scripting"),
        "CWE-91": ("Injection", "XML Injection"),
        "CWE-643": ("Injection", "XML Injection"),
        "CWE-90": ("Injection", "LDAP Injection"),
        "CWE-134": ("Injection", "Format String"),
        
        # Access Control
        "CWE-284": ("Access Control", "Missing Authorization"),
        "CWE-285": ("Access Control", "Missing Authorization"),
        "CWE-287": ("Access Control", "Broken Authentication"),
        "CWE-306": ("Access Control", "Broken Authentication"),
        "CWE-22": ("Access Control", "Path Traversal"),
        "CWE-23": ("Access Control", "Path Traversal"),
        "CWE-36": ("Access Control", "Path Traversal"),
        "CWE-269": ("Access Control", "Privilege Escalation"),
        "CWE-732": ("Access Control", "Incorrect Permissions"),
        
        # Cryptographic Issues
        "CWE-327": ("Cryptographic Issues", "Weak Encryption"),
        "CWE-328": ("Cryptographic Issues", "Weak Encryption"),
        "CWE-326": ("Cryptographic Issues", "Insufficient Entropy"),
        "CWE-330": ("Cryptographic Issues", "Insufficient Entropy"),
        "CWE-295": ("Cryptographic Issues", "Certificate Validation"),
        "CWE-320": ("Cryptographic Issues", "Key Management"),
        
        # Information Disclosure
        "CWE-200": ("Information Disclosure", "Sensitive Data Exposure"),
        "CWE-532": ("Information Disclosure", "Information Leakage"),
        "CWE-209": ("Information Disclosure", "Error Messages"),
        "CWE-538": ("Information Disclosure", "Debug Information"),
        
        # Input Validation
        "CWE-20": ("Input Validation", "Missing Validation"),
        "CWE-116": ("Input Validation", "Incorrect Input Handling"),
        "CWE-843": ("Input Validation", "Type Confusion"),
        
        # Resource Management
        "CWE-400": ("Resource Management", "Uncontrolled Resource Consumption"),
        "CWE-362": ("Resource Management", "Race Conditions"),
        "CWE-833": ("Resource Management", "Deadlocks"),
        "CWE-404": ("Resource Management", "Uncontrolled Resource Consumption"),
        
        # Insecure Design
        "CWE-1173": ("Insecure Design", "Missing Security Controls"),
        "CWE-636": ("Insecure Design", "Unsafe Defaults"),
        "CWE-501": ("Insecure Design", "Trust Boundary Violations"),
        
        # Time and State
        "CWE-367": ("Time and State", "TOCTOU"),
        "CWE-613": ("Time and State", "Session Management"),
        "CWE-384": ("Time and State", "Session Management"),
    }
    
    # Map CWEs to our categories based on the specific mappings
    for entry in cwe_entries:
        cwe_id = entry.get('cwe_id')

        if cwe_id in specific_mappings:
            category, subcategory = specific_mappings[cwe_id]
            if cwe_id not in categories[category]["cwe_ids"]:
                categories[category]["cwe_ids"].append(cwe_id)
            if cwe_id not in categories[category]["subcategories"][subcategory]:
                categories[category]["subcategories"][subcategory].append(cwe_id)
        
    # Process the CWE entries and add to appropriate category
    for entry in cwe_entries:
        cwe_id = entry.get('cwe_id')
        name = entry.get('name', '').lower()
        desc = entry.get('description', '').lower()
        
        # If already categorized in a specific mapping, skip
        if cwe_id in specific_mappings:
            continue
            
        # Try to categorize based on name and description keywords
        categorized = False
        
        # Try to categorize by keywords in name/description
        keyword_to_category = {
            r"memory|buffer|overflow|underflow|out-of-bounds|free|heap|stack|allocation": "Memory Safety",
            r"injection|sql|command|xss|cross-site|script|format string|template|ldap": "Injection",
            r"access|permission|privilege|authorization|authentication|session|csrf|trust|boundary": "Access Control",
            r"crypt|encrypt|decrypt|cipher|hash|salt|random|prng|key|certificate": "Cryptographic Issues",
            r"information disclosure|information exposure|sensitive|leak|confidential": "Information Disclosure",
            r"validation|sanitization|filter|escape|normalize|input": "Input Validation",
            r"race condition|time of check|deadlock|resource|consumption|exhaustion|denial": "Resource Management",
            r"design|insecure default|misconfiguration|unsafe": "Insecure Design",
            r"toctou|time of check|session|state": "Time and State"
        }
        
        text_to_search = f"{name} {desc}"
        for pattern, category in keyword_to_category.items():
            if re.search(pattern, text_to_search, re.IGNORECASE):
                categories[category]["cwe_ids"].append(cwe_id)
                categorized = True
                break
                
        # If still not categorized, try using CWE abstraction and structure
        if not categorized:
            if entry.get("abstraction") == "Base":
                # Look at parent relationships to infer category
                parents = entry.get('relationships', {}).get('parents', [])
                for parent_id in parents:
                    # Check if parent is in a known category
                    for category, info in categories.items():
                        if parent_id in info["cwe_ids"]:
                            if cwe_id not in info["cwe_ids"]:
                                info["cwe_ids"].append(cwe_id)
                            categorized = True
                            break
                    if categorized:
                        break
    
    # If still not categorized, put in appropriate category based on additional heuristics
    for entry in cwe_entries:
        cwe_id = entry.get('cwe_id')
        mitigations = entry.get('mitigations', [])
        mitigations_text = entry.get('mitigations_text', '')
    
    # Find which category this CWE belongs to
    for category, info in categories.items():
        if cwe_id in info["cwe_ids"]:
            # Add mitigation information
            if "mitigations" not in info:
                info["mitigations"] = {}
            
            if mitigations_text:
                info["mitigations"][cwe_id] = mitigations_text
            elif mitigations:
                info["mitigations"][cwe_id] = "; ".join([m.get("description", "") for m in mitigations if "description" in m])
        
        # Skip if already categorized
        if any(cwe_id in info["cwe_ids"] for info in categories.values()):
            continue
        
        # Look for category hints in the CWE ID number ranges
        cwe_num = 0
        if cwe_id.startswith("CWE-"):
            try:
                cwe_num = int(cwe_id[4:])
            except ValueError:
                continue
        
        # Categorize based on CWE number ranges
        if 119 <= cwe_num <= 138:  # Memory safety related CWEs
            categories["Memory Safety"]["cwe_ids"].append(cwe_id)
        elif 74 <= cwe_num <= 94:   # Injection related CWEs
            categories["Injection"]["cwe_ids"].append(cwe_id)
        elif 264 <= cwe_num <= 288:  # Access control related CWEs
            categories["Access Control"]["cwe_ids"].append(cwe_id)
        elif 310 <= cwe_num <= 340:  # Cryptography related CWEs
            categories["Cryptographic Issues"]["cwe_ids"].append(cwe_id)
        elif 200 <= cwe_num <= 213:  # Information disclosure related CWEs
            categories["Information Disclosure"]["cwe_ids"].append(cwe_id)
        elif 20 <= cwe_num <= 42:    # Input validation related CWEs
            categories["Input Validation"]["cwe_ids"].append(cwe_id)
    
    return categories

def populate_cwe_categories(db, cwe_entries, force=False):
    """Create and populate CWE categories based on parsed CWE data."""
    conn = db.connect()
    cursor = conn.cursor()
    
    try:
        logger.info("Populating CWE categories...")
        
        # Check if categories already exist
        cursor.execute("SELECT COUNT(*) FROM cwe_categories")
        category_count = cursor.fetchone()[0]
        
        if category_count > 0 and not force:
            logger.info(f"Found {category_count} existing CWE categories. Use --force to recreate.")
            return True
            
        if force and category_count > 0:
            logger.info("Removing existing CWE categories...")
            cursor.execute("DELETE FROM cwe_category_mappings")
            cursor.execute("DELETE FROM cwe_categories")
            conn.commit()
        
        # Extract category information from CWE entries
        categories = extract_cwe_categories(cwe_entries)
        
        # Insert each category and its associated CWEs
        for name, info in categories.items():
            category_data = {
                'name': name,
                'description': info['description'],
                'cwe_ids': info['cwe_ids']
            }
            db.insert_cwe_category(category_data)
            
            # Insert subcategories
            for subcat_name, subcategory_cwes in info['subcategories'].items():
                if subcategory_cwes:  # Only create subcategories that have associated CWEs
                    subcat_data = {
                        'name': subcat_name,
                        'description': f"Subcategory of {name}",
                        'parent_category': name,
                        'cwe_ids': subcategory_cwes
                    }
                    db.insert_cwe_category(subcat_data)
        
        logger.info(f"Successfully populated CWE categories")
        return True
    except Exception as e:
        conn.rollback()
        logger.error(f"Error populating CWE categories: {e}")
        return False
    finally:
        cursor.close()

def debug_vulnerability_data(db):
    """Debug vulnerability data format issues."""
    conn = db.connect()
    cursor = conn.cursor()
    
    try:
        logger.info("Debugging vulnerability data format...")
        
        # Check if vulnerabilities table has data
        cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
        vuln_count = cursor.fetchone()[0]
        logger.info(f"Found {vuln_count} vulnerabilities in database.")
        
        if vuln_count == 0:
            return False
        
        # Get a sample vulnerability
        cursor.execute("SELECT id, data FROM vulnerabilities LIMIT 1")
        sample = cursor.fetchone()
        
        if sample:
            vuln_id, data = sample
            logger.info(f"Sample vulnerability ID: {vuln_id}")
            
            # Check if data is string or JSON
            data_type = type(data).__name__
            logger.info(f"Data type: {data_type}")
            
            if isinstance(data, str):
                try:
                    parsed_data = json.loads(data)
                    logger.info(f"Data is JSON string, parsed successfully: {len(parsed_data)} fields")
                    
                    # Check for CWE field
                    if 'cwe' in parsed_data:
                        cwe_value = parsed_data['cwe']
                        cwe_type = type(cwe_value).__name__
                        logger.info(f"CWE field found, type: {cwe_type}, value: {cwe_value}")
                    else:
                        logger.warning("CWE field not found in vulnerability data")
                        
                except json.JSONDecodeError:
                    logger.error(f"Data is string but not valid JSON: {data[:100]}...")
            elif isinstance(data, dict):
                logger.info(f"Data is already a dictionary with {len(data)} fields")
                
                # Check for CWE field
                if 'cwe' in data:
                    cwe_value = data['cwe']
                    cwe_type = type(cwe_value).__name__
                    logger.info(f"CWE field found, type: {cwe_type}, value: {cwe_value}")
                else:
                    logger.warning("CWE field not found in vulnerability data")
            else:
                logger.error(f"Unexpected data type: {data_type}")
            
            # Check if CWE mapping exists for this vulnerability - FIX: Use %s for PostgreSQL
            is_postgres = hasattr(conn, 'server_version')
            if is_postgres:
                cursor.execute("SELECT cwe_id FROM vulnerability_weaknesses WHERE vuln_id = %s", (vuln_id,))
            else:
                cursor.execute("SELECT cwe_id FROM vulnerability_weaknesses WHERE vuln_id = ?", (vuln_id,))
                
            cwe_mappings = cursor.fetchall()
            
            if cwe_mappings:
                logger.info(f"Vulnerability has {len(cwe_mappings)} CWE mappings: {[cwe[0] for cwe in cwe_mappings]}")
            else:
                logger.warning("Vulnerability has no CWE mappings")
                
            # Find vulnerabilities that have non-empty CWE arrays - FIX: Different SQL syntax for PostgreSQL
            if is_postgres:
                # PostgreSQL specific JSON query 
                cursor.execute("SELECT COUNT(*) FROM vulnerabilities WHERE (data->'cwe')::jsonb @> '[]'::jsonb AND jsonb_array_length(data->'cwe') > 0")
            else:
                cursor.execute("SELECT COUNT(*) FROM vulnerabilities WHERE data LIKE '%\"cwe\":%' AND data NOT LIKE '%\"cwe\":[]%'")
                
            has_cwe_count = cursor.fetchone()[0]
            logger.info(f"Vulnerabilities with non-empty CWE field in data: {has_cwe_count} out of {vuln_count}")
        
        return True
        
    except Exception as e:
        logger.error(f"Error debugging vulnerability data: {e}")
        # Add transaction rollback to recover from errors
        try:
            conn.rollback()
        except:
            pass
        return False
    finally:
        cursor.close()
def process_vulnerability_data(db, cve_records=None, nvd_records=None, unified_records=None, force=False):
    """Process and insert vulnerability data into the database."""
    # Check if vulnerability data already exists
    conn = db.connect()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
    vuln_count = cursor.fetchone()[0]
    
    # If there are existing vulnerabilities but we don't want to force update
    if vuln_count > 0 and not force:
        logger.info(f"Vulnerability data already exists ({vuln_count} vulnerabilities). Use --force to update.")
        return True  # Return True here so CWE mappings will still be created for existing data
    
    if force and vuln_count > 0:
        logger.info(f"Deleting {vuln_count} existing vulnerability records...")
        try:
            success = db.clear_vulnerabilities()
            if not success:
                logger.error("Failed to clear vulnerability data, aborting process")
                return False
        except Exception as e:
            logger.error(f"Error clearing vulnerability data: {e}")
            return False
        
    # If we have no new data to process but have existing vulnerabilities, just return
    if not any([cve_records, nvd_records, unified_records]) and vuln_count > 0:
        logger.info("No new vulnerability data to process, using existing database records.")
        return True  # Return True so mappings will be created for existing data
        
    # Determine which data to use, preferring unified records
    records_to_insert = []
    source_type = "unknown"
    
    if unified_records:
        records_to_insert = unified_records
        source_type = "unified"
    elif nvd_records and cve_records:
        # Simple merge strategy - prefer NVD but include unique CVEs
        nvd_ids = {rec["id"] for rec in nvd_records}
        cve_unique = [rec for rec in cve_records if rec["id"] not in nvd_ids]
        records_to_insert = nvd_records + cve_unique
        source_type = "merged_nvd_cve"
    elif nvd_records:
        records_to_insert = nvd_records
        source_type = "nvd"
    elif cve_records:
        records_to_insert = cve_records
        source_type = "cve"
    
    if not records_to_insert:
        logger.warning("No vulnerability records to insert")
        return vuln_count > 0  # Return True if we have existing data, False otherwise
    
    # Apply CWE-CAPEC mappings
    try:
        capec_mapping = load_cwe_capec_mapping()
        if capec_mapping:
            logger.info("Applying CWE-CAPEC mappings...")
            records_to_insert = map_cwe_to_capec(records_to_insert, capec_mapping)
    except Exception as e:
        logger.warning(f"Error applying CWE-CAPEC mappings: {e}")
    
    # Insert records into database
    logger.info(f"Inserting {len(records_to_insert)} {source_type} vulnerability records into database...")
    
    # Skip existing records if not forcing update
    if not force and vuln_count > 0:
        # Get existing vulnerability IDs
        cursor.execute("SELECT id FROM vulnerabilities")
        existing_ids = {row[0] for row in cursor.fetchall()}
        
        # Filter out existing records
        original_count = len(records_to_insert)
        records_to_insert = [rec for rec in records_to_insert if rec.get("id") not in existing_ids]
        
        logger.info(f"Filtered out {original_count - len(records_to_insert)} existing records, {len(records_to_insert)} new records to insert")
    
    if records_to_insert:
        inserted = db.batch_insert_vulnerabilities(records_to_insert)
        if inserted:
            # For each vulnerability, extract and update patch information
            logger.info("Enhancing vulnerabilities with patch and mitigation data...")
            processed = db.process_patches_and_mitigations(limit=5000)  # Limit for performance
            logger.info(f"Enhanced {processed} vulnerabilities with patch and mitigation data")
            cursor = db.connect().cursor()
            cursor.execute("SELECT id FROM vulnerabilities")
            vuln_ids = [row[0] for row in cursor.fetchall()]
            
            for vuln_id in tqdm(vuln_ids[:5000], desc="Processing patch information"):  # Limit to 5000 for performance
                try:
                    patch_info = db.extract_patch_information(vuln_id)
                    if patch_info['has_patch']:
                        # Update the vulnerability with patch information
                        cursor.execute("""
                            UPDATE vulnerabilities SET
                            has_patch = %s,
                            patch_date = %s,
                            days_to_patch = %s,
                            patch_references = %s
                            WHERE id = %s
                        """, (
                            patch_info['has_patch'],
                            patch_info['patch_date'],
                            patch_info['days_to_patch'],
                            Json(patch_info['patch_references']) if patch_info['patch_references'] else None,
                            vuln_id
                        ))
                except Exception as e:
                    logger.warning(f"Error extracting patch info for {vuln_id}: {e}")
        logger.info(f"Successfully inserted {inserted} of {len(records_to_insert)} new vulnerability records")
        db.connect().commit()
        return True  # Inserted some records or had existing records
    else:
        logger.info("No new records to insert after filtering")
        return True  # We have existing records, so return True for further processing
    

def populate_database(args=None):
    """Process vulnerability data and populate the database based on command-line arguments."""
    if args is None:
        args = parse_args()
    
    start_time = time.time()
    
    # Ensure required directories exist
    ensure_directories()
    
    # Configure logging level
    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("\n===== DEBUG INFORMATION =====")
        logger.debug(f"Current working directory: {os.getcwd()}")
        logger.debug(f"Script location: {os.path.abspath(__file__)}")
        logger.debug("\nChecking for processed data files...")
    else:
        logger.setLevel(logging.INFO)
    
    # Initialize database based on backend selection
    logger.info("Initializing database...")
    from storage.postgresql_db import PostgresqlVulnerabilityDatabase
    db = PostgresqlVulnerabilityDatabase()
    db.initialize_schema()
    
    # Check database state before processing
    if args.debug:
        logger.debug("\nDatabase state before processing:")
        verify_database_integrity(db)
    
    # Process each data type according to arguments
    processed_something = False
    cwe_records = None
    cve_records = None
    nvd_records = None
    unified_records = None
    
    # Process CWE data first (it's used by other processes)
    if args.all or args.cwe:
        success = populate_cwe_data(db, args.raw_dir, args.processed_dir, args.force)
        if success:
            # Also populate categorizations, using the recently parsed CWE entries
            cwe_entries = db.get_all_cwe_entries()  # New method to get all CWEs from DB
            populate_cwe_categories(db, cwe_entries, args.force)
            processed_something = True
        processed_something = processed_something or success
        
        # If CWE processing was successful or exists, load the mappings
        cursor = db.connect().cursor()
        cursor.execute("SELECT COUNT(*) FROM weaknesses")
        if cursor.fetchone()[0] > 0:
            try:
                from data_processing.mappers.cwe_capec_mapper import load_cwe_capec_mapping
                cwe_capec_mapping = load_cwe_capec_mapping()
                logger.info(f"Loaded CWE-CAPEC mapping with {len(cwe_capec_mapping)} entries")
            except Exception as e:
                logger.warning(f"Could not load CWE-CAPEC mapping: {e}")
    
    # Process CAPEC data (relies on CWE data)
    if args.all or args.capec:
        processed = process_capec_data(db, args.raw_dir, args.force)
        processed_something = processed_something or processed
    
    # Process CVE data
    if args.all or args.cve:
        cve_records = process_cve_data(db, args.raw_dir, args.processed_dir, args.force, args.min_year)
        processed_something = processed_something or (cve_records is not None and len(cve_records) > 0)
    
    # Process NVD data
    if args.all or args.nvd:
        nvd_records = process_nvd_data(db, args.raw_dir, args.processed_dir, args.force)
        processed_something = processed_something or (nvd_records is not None and len(nvd_records) > 0)
    
    # Unify CVE and NVD data
    if (args.all or args.unify) and cve_records and nvd_records:
        unified_records = unify_vulnerability_data(cve_records, nvd_records, args.processed_dir)
        processed_something = processed_something or (unified_records is not None and len(unified_records) > 0)
    
    # Insert vulnerability data into database
    if args.all or args.cve or args.nvd or args.unify:
        inserted = process_vulnerability_data(db, cve_records, nvd_records, unified_records, args.force)
        
        if inserted:

            debug_vulnerability_data(db)

            # Only create CWE mappings if we successfully inserted vulnerabilities
            logger.info("Creating vulnerability-to-CWE mappings...")
            create_vulnerability_cwe_mappings(db)
            
            # Process ATT&CK data if needed
            if args.all or args.attack:
                attack_processed = process_attack_data(db, args.raw_dir, args.force)
                processed_something = processed_something or attack_processed
                
                # Only create ATT&CK mappings if both vulnerabilities and ATT&CK data exist
                if attack_processed and (args.all or args.mappings):
                    logger.info("Creating vulnerability-to-ATT&CK mappings...")
                    create_attack_mappings(db, args.force)
    
    # Verify database integrity
    if args.all or args.verify:
        verify_database_integrity(db)
    
    # Export classification data
    df = None
    if args.all or args.export or processed_something:
        df = export_classification_data(db)
    
    # Export database schema
    if args.schema or args.debug:
        export_db_schema(db, getattr(args, 'schema_path', "documentation/db_schema.sql"))
    
    # Close database connection
    db.close()
    
    elapsed_time = time.time() - start_time
    logger.info(f"Database population completed in {elapsed_time:.2f} seconds")
    
    return df

if __name__ == "__main__":
    populate_database()