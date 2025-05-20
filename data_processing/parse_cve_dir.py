"""
Module for parsing directories of CVE files.
Supports TWX's goal of unbiasing vulnerability data through proper classification.
"""

import os
import sys
import json
import logging
import re
from pathlib import Path
import traceback
from tqdm import tqdm
from datetime import datetime

# Add the project root to Python path for imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Now we can import the parse_cve module
from data_processing.parse_cve import parse_cve_record

# Set up logging
logger = logging.getLogger(__name__)

# Use an absolute path based on the project root directory
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW_CVE_BASE = os.path.join(ROOT_DIR, "data_collection", "raw_data", "cve_data", "cves")

def parse_cve_directory(directory_path=None, min_year=2021):
    """
    Parse all CVE records from the specified directory structure.
    Returns a list of normalized vulnerability records ready for database insertion.
    
    Args:
        directory_path: Directory containing CVE files (default: RAW_CVE_BASE)
        min_year: Minimum year to process (default: 2021)
        
    Returns:
        list: Normalized vulnerability records
    """
    all_records = []
    num_files = 0
    
    # Set default directory path if not provided
    if directory_path is None:
        directory_path = RAW_CVE_BASE
    
    # Check if directory exists first
    if not os.path.exists(directory_path):
        logger.error(f"Error: Directory not found: {directory_path}")
        return all_records
    
    try:
        # Get all items in the directory
        all_items = os.listdir(directory_path)
        
        # Filter for year directories only (4-digit numbers) and sort
        year_pattern = re.compile(r'^\d{4}$')
        year_dirs = [item for item in all_items 
                    if os.path.isdir(os.path.join(directory_path, item)) 
                    and year_pattern.match(item)
                    and int(item) >= min_year]
        
        # Sort years in descending order (newest first)
        year_dirs.sort(reverse=True)
        
        logger.info(f"Found year directories: {year_dirs}")
    except Exception as e:
        logger.error(f"Error accessing directory {directory_path}: {e}")
        return all_records
    
    # Process each year directory
    for year_dir in tqdm(year_dirs, desc="Processing CVE years"):
        year_path = os.path.join(directory_path, year_dir)
        logger.info(f"Processing CVEs from year {year_dir}")
        
        # Process each subdirectory in the year (normally these are ranges like "1xxx", "2xxx")
        range_dirs = []
        try:
            range_dirs = os.listdir(year_path)
        except Exception as e:
            logger.error(f"Error accessing year directory {year_path}: {e}")
            continue
            
        for range_dir in tqdm(sorted(range_dirs), desc=f"Processing {year_dir} ranges", leave=False):
            range_path = os.path.join(year_path, range_dir)
            
            # Skip if not a directory
            if not os.path.isdir(range_path):
                continue
            
            logger.debug(f"Processing range directory: {range_dir}")
            
            # Process each CVE file in the range directory
            cve_files = []
            try:
                cve_files = os.listdir(range_path)
            except Exception as e:
                logger.error(f"Error accessing range directory {range_path}: {e}")
                continue
                
            for cve_file in cve_files:
                if not cve_file.endswith('.json'):
                    continue
                
                cve_path = os.path.join(range_path, cve_file)
                num_files += 1
                
                try:
                    # Load and parse CVE file
                    with open(cve_path, 'r', encoding='utf-8') as f:
                        cve_data = json.load(f)
                    
                    # Parse the CVE record
                    parsed_record = parse_cve_record(cve_data)
                    
                    # Skip if parsing failed
                    if "parse_error" in parsed_record:
                        logger.warning(f"Error parsing {cve_path}: {parsed_record['parse_error']}")
                        continue
                    
                    # Add year to metadata
                    if "other" not in parsed_record:
                        parsed_record["other"] = {}
                    parsed_record["other"]["year"] = year_dir
                    
                    all_records.append(parsed_record)
                    
                except Exception as e:
                    logger.error(f"Error processing {cve_path}: {str(e)}")
                    if logger.level <= logging.DEBUG:
                        traceback.print_exc()
        
        logger.info(f"Completed processing {year_dir} - found {len(all_records)} valid records so far")
    
    logger.info(f"Processed {num_files} CVE files across {len(year_dirs)} years, found {len(all_records)} valid records")
    return all_records

def verify_cve_directory_structure(directory_path=None):
    """
    Verify the CVE directory structure and report what's available.
    Useful for debugging data collection issues.
    
    Args:
        directory_path: Directory to verify (default: RAW_CVE_BASE)
    """
    if directory_path is None:
        directory_path = RAW_CVE_BASE
    
    print(f"Checking CVE directory structure at: {directory_path}")
    
    if not os.path.exists(directory_path):
        print(f"ERROR: Directory does not exist: {directory_path}")
        return
    
    # List all files and directories at the root level
    root_items = os.listdir(directory_path)
    print(f"Found {len(root_items)} items in root directory")
    
    # Check for year directories (4-digit numbers)
    year_pattern = re.compile(r'^\d{4}$')
    year_dirs = [item for item in root_items 
                if os.path.isdir(os.path.join(directory_path, item)) 
                and year_pattern.match(item)]
    
    if not year_dirs:
        print("WARNING: No year directories found. Expected structure: cves/YYYY/xxxxx/CVE-YYYY-NNNNN.json")
        # List what's actually there to help diagnose
        print("Directory contents:")
        for item in root_items[:10]:  # Show first 10 items
            print(f"  - {item} ({'directory' if os.path.isdir(os.path.join(directory_path, item)) else 'file'})")
        if len(root_items) > 10:
            print(f"  ... and {len(root_items) - 10} more items")
        return
    
    print(f"Found {len(year_dirs)} year directories: {sorted(year_dirs)}")
    
    # Check some year directories for proper structure
    for year_dir in sorted(year_dirs, reverse=True)[:3]:  # Check 3 most recent years
        year_path = os.path.join(directory_path, year_dir)
        range_dirs = os.listdir(year_path)
        
        print(f"\nYear {year_dir}: Found {len(range_dirs)} range directories")
        if range_dirs:
            sample_range = range_dirs[0]
            sample_path = os.path.join(year_path, sample_range)
            cve_files = [f for f in os.listdir(sample_path) if f.endswith('.json')]
            print(f"  Sample range directory '{sample_range}': Contains {len(cve_files)} JSON files")
            if cve_files:
                print(f"  Sample file: {cve_files[0]}")

if __name__ == "__main__":
    # Configure logging for direct script execution
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # First verify the directory structure
    verify_cve_directory_structure()
    
    # Ask for confirmation before proceeding
    proceed = input("\nProceed with parsing CVE directory? (y/n): ")
    if proceed.lower() != 'y':
        print("Operation cancelled")
        sys.exit(0)
    
    # Parse CVE directory
    records = parse_cve_directory(min_year=2021)
    
    # Print summary
    print(f"Found {len(records)} valid CVE records from 2021 and newer")
    
    # Save parsed records to file
    output_dir = os.path.join(ROOT_DIR, "data_collection", "processed_data")
    output_file = os.path.join(output_dir, "cve_data_parsed_test.json")
    
    os.makedirs(output_dir, exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(records, f, indent=2)
    
    print(f"Saved {len(records)} parsed records to {output_file}")
    
    # Display sample of what was found
    if records:
        print("\nSample of parsed records:")
        for i, record in enumerate(records[:3]):
            print(f"\nRecord {i+1}:")
            print(f"  ID: {record.get('id')}")
            print(f"  Description: {record.get('description')[:100]}..." if record.get('description') else "  No description")
            print(f"  CWE: {record.get('cwe')}")
            print(f"  Year: {record.get('other', {}).get('year')}")