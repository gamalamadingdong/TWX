"""
PostgreSQL database implementation for the TWX project.

This module provides a PostgreSQL-based implementation of the vulnerability database,
supporting the project's goal of unbiasing vulnerability data through proper classification.
"""

import os
import json
import pandas as pd
import psycopg2
import psycopg2.extras
from psycopg2.extras import Json
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class PostgresqlVulnerabilityDatabase:
    """PostgreSQL implementation of the vulnerability database for the TWX project."""
    
    def __init__(self, db_name=None, user=None, password=None, host=None, port=None):
        """
        Initialize the PostgreSQL vulnerability database.
        
        Args:
            db_name: Database name (defaults to env var TWX_DB_NAME or "twx")
            user: PostgreSQL username (defaults to env var TWX_DB_USER or "postgres")
            password: PostgreSQL password (defaults to env var TWX_DB_PASSWORD)
            host: PostgreSQL host (defaults to env var TWX_DB_HOST or "localhost")
            port: PostgreSQL port (defaults to env var TWX_DB_PORT or "5432")
        """


        self.connection_params = {
            "dbname": db_name or os.environ.get('TWX_DB_NAME', 'twx'),
            "user": user or os.environ.get('TWX_DB_USER', 'postgres'),
            "password": os.environ.get('TWX_DB_PASSWORD', ''),
            "host": host or os.environ.get('TWX_DB_HOST', 'localhost'),
            "port": os.environ.get('TWX_DB_PORT', '5432')
        }
        logger.debug(f"Using database: {self.connection_params['dbname']}")

        self.conn = None
        
    def connect(self):
        """Establish database connection."""
        try:
            if self.conn is None or self.conn.closed:
                self.conn = psycopg2.connect(**self.connection_params)
            return self.conn
        except psycopg2.Error as e:
            logger.error(f"Error connecting to PostgreSQL database: {e}")
            # Try to create the database if it doesn't exist
            if "does not exist" in str(e) and self.connection_params["dbname"] == "twx":
                self._create_database()
                return self.connect()
            raise
    
    def _create_database(self):
        """Create the database if it doesn't exist."""
        temp_conn_params = self.connection_params.copy()
        temp_conn_params["dbname"] = "postgres"  # Connect to default postgres database
        
        try:
            temp_conn = psycopg2.connect(**temp_conn_params)
            temp_conn.autocommit = True
            temp_cursor = temp_conn.cursor()
            
            # Check if database exists
            temp_cursor.execute("SELECT 1 FROM pg_database WHERE datname = %s", (self.connection_params["dbname"],))
            if not temp_cursor.fetchone():
                # Create database
                temp_cursor.execute(f"CREATE DATABASE {self.connection_params['dbname']}")
                logger.info(f"Created database {self.connection_params['dbname']}")
            
            temp_cursor.close()
            temp_conn.close()
        except Exception as e:
            logger.error(f"Error creating database: {e}")
            raise
    
    def close(self):
        """Close database connection."""
        if self.conn and not self.conn.closed:
            self.conn.close()
            self.conn = None
    
    def initialize_schema(self):
        """Initialize database schema if it doesn't exist."""
        conn = self.connect()
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id TEXT PRIMARY KEY,
                    description TEXT,
                    published TIMESTAMP,
                    modified TIMESTAMP,
                    reporter TEXT,
                    source TEXT,
                    
                    -- Enhanced schema with direct columns for better querying
                    known_exploited BOOLEAN DEFAULT FALSE,
                    has_exploit BOOLEAN DEFAULT FALSE,
                    has_cisa_advisory BOOLEAN DEFAULT FALSE,
                    has_vendor_advisory BOOLEAN DEFAULT FALSE,
                    
                    base_score FLOAT,
                    severity TEXT,
                    cvss_version TEXT,
                    cvss_vector TEXT,
                    exploitability_score FLOAT,
                    impact_score FLOAT,
                    
                    attack_vector TEXT,
                    attack_complexity TEXT,
                    privileges_required TEXT,
                    user_interaction TEXT,
                    
                    primary_cwe TEXT,
                    vuln_type TEXT,
                    
                    epss_score FLOAT,
                    epss_percentile FLOAT,
                    
                    product_count INTEGER,
                    reference_count INTEGER,
                    
                    kev_date_added TIMESTAMP,
                    kev_vendor_project TEXT,
                    kev_product TEXT,
                    kev_notes TEXT,
                    kev_required_action TEXT,
                    kev_due_date TIMESTAMP,
                    
                    has_patch BOOLEAN DEFAULT FALSE,
                    patch_date TIMESTAMP,
                    days_to_patch INTEGER,
                    patch_references JSONB,
                    
                    data JSONB  -- Keep original JSON for flexibility
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS weaknesses (
                    cwe_id TEXT PRIMARY KEY,
                    name TEXT,
                    description TEXT,
                    extended_description TEXT,
                    abstraction TEXT,
                    status TEXT,
                    category TEXT,
                    relationships JSONB,
                    consequences JSONB,
                    mitigations JSONB,
                    detection_methods JSONB,
                    examples JSONB,
                    mitigations_text TEXT,
                    likelihood TEXT,
                    data JSONB
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS products (
                    id SERIAL PRIMARY KEY,
                    vendor TEXT,
                    product TEXT,
                    version TEXT,
                    UNIQUE(vendor, product, version)
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS vulnerability_products (
                    id SERIAL PRIMARY KEY,
                    vuln_id TEXT REFERENCES vulnerabilities(id) ON DELETE CASCADE,
                    product_id INTEGER REFERENCES products(id) ON DELETE CASCADE,
                    UNIQUE(vuln_id, product_id)
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS vulnerability_weaknesses (
                    id SERIAL PRIMARY KEY,
                    vuln_id TEXT REFERENCES vulnerabilities(id) ON DELETE CASCADE,
                    cwe_id TEXT REFERENCES weaknesses(cwe_id) ON DELETE CASCADE,
                    UNIQUE(vuln_id, cwe_id)
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS attack_techniques (
                    technique_id TEXT PRIMARY KEY,
                    name TEXT,
                    description TEXT,
                    tactic TEXT,
                    data JSONB
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS vulnerability_attack_mappings (
                    id SERIAL PRIMARY KEY,
                    vuln_id TEXT REFERENCES vulnerabilities(id) ON DELETE CASCADE,
                    technique_id TEXT REFERENCES attack_techniques(technique_id) ON DELETE CASCADE,
                    confidence FLOAT,
                    source TEXT,
                    UNIQUE(vuln_id, technique_id)
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS metrics (
                    id SERIAL PRIMARY KEY,
                    vuln_id TEXT REFERENCES vulnerabilities(id) ON DELETE CASCADE,
                    cvss_version TEXT,
                    base_score FLOAT,
                    vector TEXT,
                    exploitability_score FLOAT,
                    impact_score FLOAT,
                    data JSONB
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS vuln_references (
                    id SERIAL PRIMARY KEY,
                    vuln_id TEXT REFERENCES vulnerabilities(id) ON DELETE CASCADE,
                    url TEXT,
                    source TEXT,
                    tags JSONB
                )
            """)
            
            cursor.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_vuln_references_vuln_id_url 
                ON vuln_references(vuln_id, url)
            """)
            
            # Add a vulnerability-to-CAPEC mapping table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS vulnerability_capec_mappings (
                    vuln_id TEXT,
                    capec_id TEXT,
                    confidence REAL,
                    source TEXT,
                    PRIMARY KEY (vuln_id, capec_id)
                )
            """)
            
            # Add a CAPEC attack patterns table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS capec_attack_patterns (
                    capec_id TEXT PRIMARY KEY,
                    name TEXT,
                    summary TEXT,
                    likelihood TEXT,
                    severity TEXT,
                    data JSONB
                )
            """)
            
            # Add a CWE-to-CAPEC mapping table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cwe_capec_mappings (
                    cwe_id TEXT,
                    capec_id TEXT,
                    confidence REAL,
                    PRIMARY KEY (cwe_id, capec_id)
                )
            """)
            
            # Add a CAPEC-to-ATT&CK mapping table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS capec_attack_mappings (
                    capec_id TEXT,
                    technique_id TEXT,
                    confidence REAL,
                    source TEXT,
                    PRIMARY KEY (capec_id, technique_id)
                )
            """)
            
            # Add these tables to the initialize_schema method
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cwe_categories (
                    id SERIAL PRIMARY KEY,
                    name TEXT UNIQUE,
                    description TEXT,
                    parent_category TEXT
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cwe_category_mappings (
                    id SERIAL PRIMARY KEY,
                    cwe_id TEXT REFERENCES weaknesses(cwe_id) ON DELETE CASCADE,
                    category_id INTEGER REFERENCES cwe_categories(id) ON DELETE CASCADE,
                    UNIQUE(cwe_id, category_id)
                )
            """)

            cursor.execute("""
                ALTER TABLE vulnerabilities
                ADD COLUMN IF NOT EXISTS has_patch BOOLEAN DEFAULT FALSE,
                ADD COLUMN IF NOT EXISTS patch_date TIMESTAMP,
                ADD COLUMN IF NOT EXISTS days_to_patch INTEGER,
                ADD COLUMN IF NOT EXISTS patch_references JSONB,
                ADD COLUMN IF NOT EXISTS mitigation_info TEXT
            """)

            # Create indexes
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_cwe_categories_name ON cwe_categories(name)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_cwe_categories_parent ON cwe_categories(parent_category)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_published ON vulnerabilities(published)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_modified ON vulnerabilities(modified)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_known_exploited ON vulnerabilities(known_exploited)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_base_score ON vulnerabilities(base_score)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_attack_vector ON vulnerabilities(attack_vector)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_attack_complexity ON vulnerabilities(attack_complexity)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_primary_cwe ON vulnerabilities(primary_cwe)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_vuln_type ON vulnerabilities(vuln_type)")
                        
                        # Create indexes
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_source ON vulnerabilities(source)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_products_vendor ON products(vendor)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_products_product ON products(product)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_weaknesses_category ON weaknesses(category)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_attack_techniques_tactic ON attack_techniques(tactic)")
            
            # Create a GIN index for the JSONB data column in vulnerabilities
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_data_gin ON vulnerabilities USING GIN (data jsonb_path_ops)")
            
            # Create a text search index for vulnerability descriptions
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_description_tsvector ON vulnerabilities USING GIN (to_tsvector('english', description))")
            
            conn.commit()
            logger.info("Database schema initialized successfully")
            
        except Exception as e:
            conn.rollback()
            logger.error(f"Error initializing database schema: {e}")
            raise
        finally:
            cursor.close()

    def get_vulnerabilities_by_mitigation_status(self, has_mitigation=True, limit=100):
        """
        Query vulnerabilities by mitigation status.
        
        Args:
            has_mitigation: Whether to return vulnerabilities with or without mitigations
            limit: Maximum number of results to return
            
        Returns:
            List of vulnerability records
        """
        conn = self.connect()
        cursor = conn.cursor()
        
        try:
            if has_mitigation:
                query = """
                    SELECT v.*, w.mitigations_text
                    FROM vulnerabilities v
                    JOIN vulnerability_weaknesses vw ON v.id = vw.vuln_id
                    JOIN weaknesses w ON vw.cwe_id = w.cwe_id
                    WHERE w.mitigations_text IS NOT NULL AND w.mitigations_text != ''
                    LIMIT %s
                """
            else:
                query = """
                    SELECT v.*
                    FROM vulnerabilities v
                    LEFT JOIN vulnerability_weaknesses vw ON v.id = vw.vuln_id
                    LEFT JOIN weaknesses w ON vw.cwe_id = w.cwe_id
                    WHERE w.mitigations_text IS NULL OR w.mitigations_text = ''
                    LIMIT %s
                """
                
            cursor.execute(query, (limit,))
            results = cursor.fetchall()
            return results
        except Exception as e:
            logger.error(f"Error querying vulnerabilities by mitigation status: {e}")
            return []
        finally:
            cursor.close()      
    def extract_patch_information(self, vulnerability_id):
        """
        Extract patch information for a vulnerability.
        
        Args:
            vulnerability_id: ID of the vulnerability
            
        Returns:
            dict: Patch information including has_patch, patch_date, days_to_patch, references
        """
        conn = self.connect()
        cursor = conn.cursor()
        
        patch_info = {
            'has_patch': False,
            'patch_date': None,
            'days_to_patch': None,
            'patch_references': []
        }
        
        try:
            # Query for references with patch-related tags
            cursor.execute("""
                SELECT vr.url, vr.tags, v.published 
                FROM vuln_references vr
                JOIN vulnerabilities v ON vr.vuln_id = v.id
                WHERE vr.vuln_id = %s
            """, (vulnerability_id,))
            
            references = cursor.fetchall()
            
            for url, tags, published_date in references:
                if not tags:
                    continue
                    
                # Check for patch-related tags
                tag_list = []
                if isinstance(tags, list):
                    tag_list = tags
                elif isinstance(tags, str):
                    try:
                        tag_list = json.loads(tags)
                    except:
                        continue
                elif isinstance(tags, dict):
                    # Handle any other formats as needed
                    continue
                    
                # Check if any relevant tags are in the list
                patch_tags = ['Patch', 'Fix', 'Vendor Advisory', 'Issue Tracking']
                if any(tag in tag_list for tag in patch_tags):
                    patch_info['has_patch'] = True
                    patch_info['patch_references'].append(url)
                    
                    # Try to determine patch date - this would require looking at the specific URL
                    # or possibly other metadata that might be available
            
            try:
                # After checking references for patch tag
                
                # If we found patches but no patch date, use a better heuristic
                if patch_info['has_patch'] and not patch_info['patch_date']:
                    cursor.execute("""
                        SELECT published, modified FROM vulnerabilities
                        WHERE id = %s
                    """, (vulnerability_id,))
                    
                    dates = cursor.fetchone()
                    if dates:
                        published, modified = dates
                        
                        # If we have both dates and modified is later than published,
                        # it likely represents a patch update
                        if published and modified and modified > published:
                            # Use modified date as patch date
                            patch_info['patch_date'] = modified
                            
                            # Calculate days to patch
                            delta = modified - published
                            patch_info['days_to_patch'] = delta.days
                        elif modified:
                            # If no published date or dates are equal, just use modified as patch date
                            patch_info['patch_date'] = modified
                        else:
                            # Last resort - use published date
                            patch_info['patch_date'] = published

                # If we have both a patch date and modified date, use the earlier one
                if patch_info['patch_date'] and modified:
                    # If modified date is before patch date, it might be when issue was fixed
                    if modified < patch_info['patch_date']:
                        patch_info['patch_date'] = modified

                # Calculate days_to_patch whenever possible
                if published and (patch_info['patch_date'] or modified):
                    effective_patch_date = patch_info['patch_date'] or modified
                    patch_info['days_to_patch'] = (effective_patch_date - published).days

            except Exception as e:
                logger.debug(f"Error calculating days to patch for {vulnerability_id}: {e}")

            return patch_info
            
        except Exception as e:
            logger.error(f"Error extracting patch information for {vulnerability_id}: {e}")
            return patch_info
        finally:
            cursor.close()
    def insert_cwe_category(self, category_data):
        """Insert or update a CWE category with its associated CWEs."""
        conn = self.connect()
        cursor = conn.cursor()
        
        try:
            category_name = category_data.get('name')
            description = category_data.get('description', '')
            parent_category = category_data.get('parent_category', '')
            cwe_ids = category_data.get('cwe_ids', [])
            
            # Insert the category
            cursor.execute("""
                INSERT INTO cwe_categories (name, description, parent_category)
                VALUES (%s, %s, %s)
                ON CONFLICT (name) DO UPDATE SET
                description = EXCLUDED.description,
                parent_category = EXCLUDED.parent_category
                RETURNING id
            """, (category_name, description, parent_category))
            
            category_id = cursor.fetchone()[0]
            
            # Associate CWEs with this category
            for cwe_id in cwe_ids:
                cursor.execute("""
                    INSERT INTO cwe_category_mappings (cwe_id, category_id)
                    VALUES (%s, %s)
                    ON CONFLICT (cwe_id, category_id) DO NOTHING
                """, (cwe_id, category_id))
            
            conn.commit()
            return True
        except Exception as e:
            conn.rollback()
            logger.error(f"Error inserting CWE category {category_data.get('name')}: {e}")
            return False
        finally:
            cursor.close()

    def extract_mitigation_information(self, vulnerability_id):
        """
        Extract mitigation information for a vulnerability.
        
        Args:
            vulnerability_id: ID of the vulnerability
            
        Returns:
            dict: Mitigation information including sources and text
        """
        conn = self.connect()
        cursor = conn.cursor()
        
        mitigation_info = {
            'has_mitigation': False,
            'reference_mitigations': [],
            'cwe_mitigations': [],
            'mitigation_text': ''
        }
        
        try:
            # Check for mitigation information in references
            cursor.execute("""
                SELECT vr.url, vr.tags, vr.source 
                FROM vuln_references vr
                WHERE vr.vuln_id = %s
            """, (vulnerability_id,))
            
            references = cursor.fetchall()
            
            for url, tags, source in references:
                if not tags:
                    continue
                    
                tag_list = []
                if isinstance(tags, list):
                    tag_list = tags
                elif isinstance(tags, str):
                    try:
                        tag_list = json.loads(tags)
                    except:
                        continue
                elif isinstance(tags, dict):
                    continue
                    
                # Check if any mitigation-related tags are in the list
                mitigation_tags = ['Mitigation', 'Patch', 'Fix', 'Vendor Advisory', 'Solution', 'Workaround']
                if any(tag in tag_list for tag in mitigation_tags):
                    mitigation_info['has_mitigation'] = True
                    mitigation_info['reference_mitigations'].append({
                        'url': url,
                        'source': source,
                        'tags': tag_list
                    })
            
            # Get mitigation information from associated CWEs
            cursor.execute("""
                SELECT w.cwe_id, w.mitigations_text 
                FROM vulnerability_weaknesses vw
                JOIN weaknesses w ON vw.cwe_id = w.cwe_id
                WHERE vw.vuln_id = %s AND w.mitigations_text IS NOT NULL AND w.mitigations_text != ''
            """, (vulnerability_id,))
            
            cwe_mitigations = cursor.fetchall()
            
            for cwe_id, mitigation_text in cwe_mitigations:
                if mitigation_text:
                    mitigation_info['has_mitigation'] = True
                    mitigation_info['cwe_mitigations'].append({
                        'cwe_id': cwe_id,
                        'mitigation_text': mitigation_text
                    })
                    
            # Compile all mitigation text into a single field for easy querying
            all_texts = []
            
            # Add CWE mitigation texts
            for cwe_mitigation in mitigation_info['cwe_mitigations']:
                all_texts.append(f"[CWE-{cwe_mitigation['cwe_id']}]: {cwe_mitigation['mitigation_text']}")
            
            # Add reference to mitigation sources
            for ref in mitigation_info['reference_mitigations']:
                all_texts.append(f"[{ref['source']}]: {ref['url']}")
            
            # Join all mitigation texts
            if all_texts:
                mitigation_info['mitigation_text'] = " | ".join(all_texts)
            
            return mitigation_info
            
        except Exception as e:
            logger.error(f"Error extracting mitigation information for {vulnerability_id}: {e}")
            return mitigation_info
        finally:
            cursor.close()


    def check_schema_fields(self):
        """Verify all required fields exist in the schema and add them if missing."""
        conn = self.connect()
        cursor = conn.cursor()
        
        try:
            # Check for patch and mitigation fields
            cursor.execute("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = 'vulnerabilities'
            """)
            
            columns = [row[0] for row in cursor.fetchall()]
            
            # Add missing columns if needed
            if 'has_patch' not in columns:
                cursor.execute("""
                    ALTER TABLE vulnerabilities 
                    ADD COLUMN has_patch BOOLEAN DEFAULT FALSE
                """)
                
            if 'patch_date' not in columns:
                cursor.execute("""
                    ALTER TABLE vulnerabilities 
                    ADD COLUMN patch_date TIMESTAMP
                """)
                
            if 'days_to_patch' not in columns:
                cursor.execute("""
                    ALTER TABLE vulnerabilities 
                    ADD COLUMN days_to_patch INTEGER
                """)
                
            if 'patch_references' not in columns:
                cursor.execute("""
                    ALTER TABLE vulnerabilities 
                    ADD COLUMN patch_references JSONB
                """)
                
            if 'mitigation_info' not in columns:
                cursor.execute("""
                    ALTER TABLE vulnerabilities 
                    ADD COLUMN mitigation_info TEXT
                """)
                
            conn.commit()
            return True
            
        except Exception as e:
            conn.rollback()
            logger.error(f"Error checking schema fields: {e}")
            return False
        finally:
            cursor.close()
    def process_patches_and_mitigations(self, limit=5000):
        """Process patches and mitigations for vulnerabilities in batches."""
        conn = self.connect()
        cursor = conn.cursor()
        
        try:
            # Check if the necessary fields exist in the schema
            self.check_schema_fields()
            
            # Get vulnerabilities to process
            cursor.execute(f"SELECT id FROM vulnerabilities ORDER BY published DESC LIMIT {limit}")
            vuln_ids = [row[0] for row in cursor.fetchall()]
            
            logger.info(f"Processing patch and mitigation data for {len(vuln_ids)} vulnerabilities...")
            
            # Process in batches for better performance
            batch_size = 100
            processed = 0
            
            for i in range(0, len(vuln_ids), batch_size):
                batch = vuln_ids[i:i+batch_size]
                
                for vuln_id in batch:
                    # Extract patch and mitigation information
                    patch_info = self.extract_patch_information(vuln_id)
                    mitigation_info = self.extract_mitigation_information(vuln_id)
                    
                    # Update the vulnerability with both sets of information
                    cursor.execute("""
                        UPDATE vulnerabilities SET
                        has_patch = %s,
                        patch_date = %s,
                        days_to_patch = %s,
                        patch_references = %s,
                        mitigation_info = %s
                        WHERE id = %s
                    """, (
                        patch_info['has_patch'],
                        patch_info['patch_date'],
                        patch_info['days_to_patch'],
                        Json(patch_info['patch_references']) if patch_info['patch_references'] else None,
                        mitigation_info['mitigation_text'],
                        vuln_id
                    ))
                    
                    processed += 1
                
                # Commit after each batch
                conn.commit()
                logger.info(f"Processed {min(i+batch_size, len(vuln_ids))}/{len(vuln_ids)} vulnerabilities")
            
            logger.info(f"Successfully processed patch and mitigation data for {processed} vulnerabilities")
            return processed
        except Exception as e:
            conn.rollback()
            logger.error(f"Error processing patches and mitigations: {e}")
            return 0
        finally:
            cursor.close()
    def export_to_json(self, output_path="analysis/classification_data.json"):
        """
        Export vulnerability data for classification and analysis in JSON format.
        
        Args:
            output_path: Path where JSON file will be saved
            
        Returns:
            DataFrame: Pandas DataFrame with classification data
        """
        # Create a fresh connection
        conn = self.connect()
        if hasattr(conn, 'status') and conn.status == psycopg2.extensions.STATUS_IN_TRANSACTION:
            conn.rollback()
        
        try:
            logger.info(f"Exporting classification data to JSON: {output_path}")
            
            # Execute the same SQL query from export_to_csv
            query = """
            SELECT 
                v.id as vuln_id,
                v.description,
                v.published,
                v.modified,
                v.reporter,
                v.source,
                
                -- Exploitation and security data
                COALESCE(v.known_exploited, FALSE) AS known_exploited,
                COALESCE(v.has_exploit, FALSE) AS has_exploit,
                COALESCE(v.has_cisa_advisory, FALSE) AS has_cisa_advisory,
                COALESCE(v.has_vendor_advisory, FALSE) AS has_vendor_advisory,
                COALESCE(v.has_patch, FALSE) AS has_patch,
                
                -- CVSS and scoring data
                v.base_score,
                v.severity,
                v.cvss_version,
                v.cvss_vector,
                v.exploitability_score,
                v.impact_score,
                
                -- Attack characteristics
                v.attack_vector,
                v.attack_complexity,
                v.privileges_required,
                v.user_interaction,
                
                -- Classification data
                v.primary_cwe,
                v.vuln_type,
                
                -- Patch and mitigation data
                v.patch_date,
                v.days_to_patch,
                v.mitigation_info,
                
                -- Vendor/product info (crucial for proper filtering)
                string_agg(DISTINCT p.vendor, ',') AS vendors,
                string_agg(DISTINCT p.product, ',') AS products,
                
                -- Other metadata 
                v.product_count,
                v.reference_count,
                v.epss_score,
                v.epss_percentile,
                string_agg(DISTINCT vw.cwe_id, ',') AS cwe_ids,
                string_agg(DISTINCT at.technique_id, ',') AS attack_techniques,
                string_agg(DISTINCT at.tactic, ',') AS attack_tactics
            FROM
                vulnerabilities v
                LEFT JOIN vulnerability_weaknesses vw ON v.id = vw.vuln_id
                LEFT JOIN weaknesses w ON vw.cwe_id = w.cwe_id
                LEFT JOIN vulnerability_products vp ON v.id = vp.vuln_id  
                LEFT JOIN products p ON vp.product_id = p.id
                LEFT JOIN vulnerability_attack_mappings vam ON v.id = vam.vuln_id
                LEFT JOIN attack_techniques at ON vam.technique_id = at.technique_id
            GROUP BY
                v.id, v.description, v.published, v.modified, v.reporter, v.source,
                v.known_exploited, v.has_exploit, v.has_cisa_advisory, v.has_vendor_advisory,
                v.base_score, v.severity, v.cvss_version, v.cvss_vector,
                v.exploitability_score, v.impact_score, v.attack_vector,
                v.attack_complexity, v.privileges_required, v.user_interaction,
                v.primary_cwe, v.vuln_type, v.has_patch, v.patch_date, v.days_to_patch,
                v.mitigation_info, v.product_count, v.reference_count, v.epss_score, v.epss_percentile
            ORDER BY v.published DESC
            """
            
            # Load into DataFrame first for processing
            df = pd.read_sql_query(query, conn)
            
            # Process dates
            for date_col in ['published', 'modified', 'patch_date']:
                if date_col in df.columns:
                    df[date_col] = pd.to_datetime(df[date_col], errors='coerce')
            
            # Save to both formats for backward compatibility
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            # Before saving the JSON, add some metadata
            metadata = {
                "export_date": datetime.now().isoformat(),
                "record_count": len(df),
                "twx_version": "1.0.0",  # Add your version
                "fields": list(df.columns)
            }

            # Save metadata separately
            with open(output_path.replace('.json', '_metadata.json'), 'w') as f:
                json.dump(metadata, f, indent=2)
            # Save as JSON - orient='records' creates a list of dicts, most compatible format
            df.to_json(output_path, orient='records', date_format='iso')
            logger.info(f"Exported {len(df)} records to {output_path}")
            
            # Also save as CSV for backward compatibility (temporary)
            csv_path = output_path.replace('.json', '.csv')
            df.to_csv(csv_path, index=False)
            logger.info(f"Also exported to CSV at {csv_path} for compatibility")
            
            # Create a smaller sample file for inspection
            sample_path = output_path.replace('.json', '_sample.json')
            df.head(50).to_json(sample_path, orient='records', date_format='iso')
            
            return df
            
        except Exception as e:
            logger.error(f"Error exporting classification data to JSON: {e}")
            # Try fallback method for critical errors
            try:
                # Basic query for fallback
                fallback_query = """
                SELECT id as vuln_id, description, published, modified 
                FROM vulnerabilities 
                ORDER BY published DESC LIMIT 1000
                """
                df = pd.read_sql_query(fallback_query, conn)
                
                # Save fallback JSON
                fallback_path = output_path.replace('.json', '_fallback.json')
                df.to_json(fallback_path, orient='records')
                logger.info(f"Saved fallback data to {fallback_path}")
                
                return df
            except Exception as e2:
                logger.error(f"Fallback JSON export also failed: {e2}")
                return pd.DataFrame()
    def batch_insert_cwes(self, cwes):
        """Insert multiple CWE records in batch with progress reporting."""
        conn = self.connect()
        original_autocommit = conn.autocommit
        cursor = conn.cursor()
        
        count = 0
        batch_size = 50
        total = len(cwes)
        
        try:
            # Set autocommit to False for transaction
            if original_autocommit:
                conn.autocommit = False
                
            for i in range(0, total, batch_size):
                batch = cwes[i:i+batch_size]
                for cwe in batch:
                    success = self.insert_cwe(cwe)
                    if success:
                        count += 1
                
                # Commit after each batch
                conn.commit()
                logger.info(f"Processed {min(i+batch_size, total)}/{total} CWE entries, {count} successful")
            
            return count
        except Exception as e:
            conn.rollback()
            logger.error(f"Error in batch CWE insert: {e}")
            return count
        finally:
            cursor.close()
            # Restore original autocommit state
            if not conn.closed:
                try:
                    conn.commit()
                    conn.autocommit = original_autocommit
                except psycopg2.Error:
                    pass

    def batch_insert_vulnerabilities(self, vulns):
        """Insert multiple vulnerability records in batch."""
        conn = self.connect()
        # Store original autocommit state
        original_autocommit = conn.autocommit
        cursor = conn.cursor()
        
        count = 0
        batch_size = 100
        total = len(vulns)
        
        try:
            # Set autocommit to False *before* any transaction begins
            if original_autocommit:
                conn.autocommit = False
                
            for i in range(0, total, batch_size):
                batch = vulns[i:i+batch_size]
                for vuln in batch:
                    success = self.insert_vulnerability(vuln)
                    if success:
                        count += 1
                
                # Commit after each batch
                conn.commit()
                logger.info(f"Processed {min(i+batch_size, total)}/{total} vulnerabilities, {count} successful")
            
            return count
        except Exception as e:
            conn.rollback()
            logger.error(f"Error in batch insert: {e}")
            return count
        finally:
            cursor.close()
            # Restore original autocommit state correctly (outside any transaction)
            if not conn.closed:
                try:
                    # Make sure we're not in a transaction by committing any pending work
                    conn.commit() 
                    conn.autocommit = original_autocommit
                except psycopg2.Error:
                    # If error occurs during commit, let's not worry about autocommit
                    pass

    # Add this as a static method in the PostgresqlVulnerabilityDatabase class
    def populate_cwe_categories(self):
        """Populate standard CWE categories for better classification."""
        conn = self.connect()
        cursor = conn.cursor()
        
        # Define standard CWE categories for the TWX project
        categories = [
            {"name": "Memory Safety", "description": "Vulnerabilities related to memory management", 
            "cwes": ["CWE-119", "CWE-120", "CWE-125", "CWE-416", "CWE-476", "CWE-787"]},
            {"name": "Injection", "description": "Vulnerabilities allowing injection of malicious data",
            "cwes": ["CWE-74", "CWE-77", "CWE-78", "CWE-79", "CWE-89", "CWE-94"]},
            {"name": "Access Control", "description": "Authentication and authorization vulnerabilities",
            "cwes": ["CWE-22", "CWE-264", "CWE-284", "CWE-285", "CWE-287", "CWE-306"]},
            {"name": "Cryptographic Issues", "description": "Vulnerabilities in cryptographic implementations",
            "cwes": ["CWE-295", "CWE-310", "CWE-327", "CWE-328", "CWE-329", "CWE-330"]},
            {"name": "Information Disclosure", "description": "Vulnerabilities leading to sensitive data exposure",
            "cwes": ["CWE-200", "CWE-203", "CWE-209", "CWE-532", "CWE-538"]},
            {"name": "Deserialization", "description": "Vulnerabilities in deserialization processes",
            "cwes": ["CWE-502", "CWE-571"]},
            {"name": "Resource Management", "description": "Vulnerabilities in system resource handling",
            "cwes": ["CWE-400", "CWE-770", "CWE-772", "CWE-835"]},
            {"name": "Race Conditions", "description": "Timing-related vulnerabilities",
            "cwes": ["CWE-362", "CWE-364", "CWE-366", "CWE-367"]}
        ]
        
        try:
            for category in categories:
                # Insert category
                cursor.execute("""
                    INSERT INTO cwe_categories (name, description)
                    VALUES (%s, %s)
                    ON CONFLICT (name) DO UPDATE SET
                    description = EXCLUDED.description
                    RETURNING id
                """, (category["name"], category["description"]))
                
                category_id = cursor.fetchone()[0]
                
                # Map CWEs to this category
                for cwe_id in category["cwes"]:
                    cursor.execute("""
                        INSERT INTO cwe_category_mappings (cwe_id, category_id)
                        VALUES (%s, %s)
                        ON CONFLICT (cwe_id, category_id) DO NOTHING
                    """, (cwe_id, category_id))
            
            conn.commit()
            logger.info(f"Successfully populated {len(categories)} CWE categories")
            return True
        except Exception as e:
            conn.rollback()
            logger.error(f"Error populating CWE categories: {e}")
            return False
        finally:
            cursor.close()

    @staticmethod
    def extract_element_text(element):
        """Extract text content from an XML element, handling nested elements."""
        if element is None:
            return ""
            
        # If this is a simple element with just text
        if len(element) == 0:
            return element.text or ""
            
        # For elements with nested content, concatenate all text
        text_parts = []
        if element.text:
            text_parts.append(element.text.strip())
            
        for child in element:
            # Recursively get text from children
            child_text = PostgresqlVulnerabilityDatabase.extract_element_text(child)
            if child_text:
                text_parts.append(child_text.strip())
            if child.tail:
                text_parts.append(child.tail.strip())
                
        return " ".join(text_parts)
    
    def insert_cwe(self, cwe):
        """Insert or update a CWE record."""
        conn = self.connect()
        cursor = conn.cursor()
        
        try:
            # Extract primary fields
            cwe_id = cwe.get('cwe_id')
            name = cwe.get('name', '')
            description = cwe.get('description', '')
            extended_description = cwe.get('extended_description', '')
            abstraction = cwe.get('abstraction', '')
            status = cwe.get('status', '')
            category = cwe.get('category', '')
            
            # Extract relationship data
            relationships = cwe.get('relationships', {})
            consequences = cwe.get('consequences', [])
            mitigations = cwe.get('mitigations', [])
            detection_methods = cwe.get('detection_methods', [])
            examples = cwe.get('examples', [])
            likelihood = cwe.get('likelihood', '')
            
            # Extract mitigations text from the mitigations list
            mitigations_text = cwe.get('mitigations_text', '')
            if not mitigations_text and mitigations:
                # Join all mitigation descriptions with a separator
                mitigations_text = "; ".join([m.get("description", "") for m in mitigations if "description" in m])
            
            # Insert or update CWE
            cursor.execute("""
                INSERT INTO weaknesses (
                    cwe_id, name, description, extended_description, abstraction, 
                    status, category, relationships, consequences, mitigations,
                    detection_methods, examples, mitigations_text, likelihood, data
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (cwe_id) DO UPDATE SET
                name = EXCLUDED.name,
                description = EXCLUDED.description,
                extended_description = EXCLUDED.extended_description,
                abstraction = EXCLUDED.abstraction,
                status = EXCLUDED.status,
                category = EXCLUDED.category,
                relationships = EXCLUDED.relationships,
                consequences = EXCLUDED.consequences,
                mitigations = EXCLUDED.mitigations,
                detection_methods = EXCLUDED.detection_methods,
                examples = EXCLUDED.examples,
                mitigations_text = EXCLUDED.mitigations_text,
                likelihood = EXCLUDED.likelihood,
                data = EXCLUDED.data
            """, (
                cwe_id, name, description, extended_description, abstraction,
                status, category, Json(relationships), Json(consequences), Json(mitigations),
                Json(detection_methods), Json(examples), mitigations_text, likelihood, Json(cwe)
            ))
            
            conn.commit()
            return True
        except Exception as e:
            conn.rollback()
            logger.error(f"Error inserting CWE {cwe.get('cwe_id')}: {e}")
            return False
        finally:
            cursor.close()

    def insert_attack_technique(self, technique):
        """Insert or update an ATT&CK technique."""
        conn = self.connect()
        cursor = conn.cursor()
        
        try:
            technique_id = technique.get('technique_id')
            name = technique.get('name', '')
            description = technique.get('description', '')
            tactic = technique.get('tactic', '')
            
            cursor.execute("""
                INSERT INTO attack_techniques (technique_id, name, description, tactic, data)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (technique_id) DO UPDATE SET
                name = EXCLUDED.name,
                description = EXCLUDED.description,
                tactic = EXCLUDED.tactic,
                data = EXCLUDED.data
            """, (technique_id, name, description, tactic, Json(technique)))
            
            conn.commit()
            return True
        except Exception as e:
            conn.rollback()
            logger.error(f"Error inserting ATT&CK technique {technique.get('technique_id')}: {e}")
            return False
        finally:
            cursor.close()

    def create_vulnerability_attack_mapping(self, vuln_id, technique_id, confidence=0.8, source="manual"):
        """Create a mapping between vulnerability and ATT&CK technique."""
        conn = self.connect()
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                INSERT INTO vulnerability_attack_mappings (vuln_id, technique_id, confidence, source)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (vuln_id, technique_id) DO UPDATE SET
                confidence = EXCLUDED.confidence,
                source = EXCLUDED.source
            """, (vuln_id, technique_id, confidence, source))
            
            conn.commit()
            return True
        except Exception as e:
            conn.rollback()
            logger.error(f"Error creating mapping between {vuln_id} and {technique_id}: {e}")
            return False
        finally:
            cursor.close()

    def insert_capec(self, capec):
        """Insert or update a CAPEC attack pattern."""
        conn = self.connect()
        cursor = conn.cursor()
        
        try:
            capec_id = capec.get('capec_id')
            name = capec.get('name', '')
            summary = capec.get('summary', '')
            likelihood = capec.get('likelihood', '')
            severity = capec.get('severity', '')
            related_weaknesses = capec.get('related_weaknesses', [])
            
            # Insert CAPEC data
            cursor.execute("""
                INSERT INTO capec_attack_patterns (capec_id, name, summary, likelihood, severity, data)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (capec_id) DO UPDATE SET
                name = EXCLUDED.name,
                summary = EXCLUDED.summary,
                likelihood = EXCLUDED.likelihood,
                severity = EXCLUDED.severity,
                data = EXCLUDED.data
            """, (capec_id, name, summary, likelihood, severity, Json(capec)))
            
            # Create CWE-CAPEC mappings
            for cwe_id in related_weaknesses:
                if cwe_id:
                    cursor.execute("""
                        INSERT INTO cwe_capec_mappings (cwe_id, capec_id, confidence)
                        VALUES (%s, %s, %s)
                        ON CONFLICT (cwe_id, capec_id) DO NOTHING
                    """, (cwe_id, capec_id, 1.0))
            
            conn.commit()
            return True
        except Exception as e:
            conn.rollback()
            logger.error(f"Error inserting CAPEC {capec.get('capec_id')}: {e}")
            return False
        finally:
            cursor.close()
            
    def export_to_csv(self, output_path="analysis/classification_data.csv"):
        """
        Export comprehensive classification data to CSV for analysis.
        
        This function creates a rich dataset by joining the vulnerability data with related
        tables (products, weaknesses, attack techniques, etc.) to provide a complete
        view of the vulnerability landscape that can be used for classification and analysis.
        
        Args:
            output_path: Path where the CSV file will be saved
            
        Returns:
            DataFrame: Pandas DataFrame with the exported data
        """
        logger.info(f"Exporting classification data to {output_path}")
        
        try:
            conn = self.connect()
            
            # Query that properly joins all relevant tables to create a rich dataset
            # for vulnerability classification and analysis
            query = """
            SELECT
                -- Core vulnerability data
                v.id AS vuln_id,
                v.description,
                v.published,
                v.modified,
                v.reporter,
                v.source,
                
                -- Exploitation data
                COALESCE(v.known_exploited, FALSE) AS known_exploited,
                COALESCE(v.has_exploit, FALSE) AS has_exploit,
                COALESCE(v.has_cisa_advisory, FALSE) AS has_cisa_advisory,
                COALESCE(v.has_vendor_advisory, FALSE) AS has_vendor_advisory,
                
                -- CVSS metrics
                v.base_score,
                v.severity,
                v.cvss_version,
                v.cvss_vector,
                v.exploitability_score,
                v.impact_score,
                
                -- Attack characteristics
                v.attack_vector,
                v.attack_complexity,
                v.privileges_required,
                v.user_interaction,
                
                -- Classification data
                v.primary_cwe,
                v.vuln_type,
                
                -- EPSS data
                v.epss_score,
                v.epss_percentile,
                
                -- Metadata counts
                COALESCE(v.product_count, 0) AS product_count,
                COALESCE(v.reference_count, 0) AS reference_count,
                
                -- KEV data
                v.kev_date_added,
                v.kev_vendor_project,
                v.kev_product,
                v.kev_notes,
                v.kev_required_action,
                v.kev_due_date,
                
                -- Related data through joins
                -- Get CWE IDs as comma-separated list
                string_agg(DISTINCT vw.cwe_id, ',') AS cwe_ids,
                
                -- Get CWE categories
                string_agg(DISTINCT w.category, ',') AS cwe_categories,
                
                -- Get affected vendors and products
                string_agg(DISTINCT p.vendor, ',') AS vendors,
                string_agg(DISTINCT p.product, ',') AS products,
                
                -- Attack mapping data
                CASE 
                    WHEN EXISTS (SELECT 1 FROM vulnerability_attack_mappings WHERE vuln_id = v.id) 
                    THEN TRUE ELSE FALSE 
                END AS has_attack_mapping,
                
                -- Get ATT&CK data
                string_agg(DISTINCT at.technique_id, ',') AS attack_techniques,
                string_agg(DISTINCT at.tactic, ',') AS attack_tactics,
                
                -- Derived fields for analysis
                CASE
                    WHEN v.attack_vector = 'NETWORK' OR v.attack_vector = 'Network' THEN TRUE
                    ELSE FALSE
                END AS remote_exploitable
                
            FROM
                vulnerabilities v
                -- Join to get CWEs
                LEFT JOIN vulnerability_weaknesses vw ON v.id = vw.vuln_id
                LEFT JOIN weaknesses w ON vw.cwe_id = w.cwe_id
                
                -- Join to get products
                LEFT JOIN vulnerability_products vp ON v.id = vp.vuln_id
                LEFT JOIN products p ON vp.product_id = p.id
                
                -- Join to get ATT&CK techniques
                LEFT JOIN vulnerability_attack_mappings vam ON v.id = vam.vuln_id
                LEFT JOIN attack_techniques at ON vam.technique_id = at.technique_id
                
            GROUP BY
                v.id, v.description, v.published, v.modified, v.reporter, v.source,
                v.known_exploited, v.has_exploit, v.has_cisa_advisory, v.has_vendor_advisory,
                v.base_score, v.severity, v.cvss_version, v.cvss_vector,
                v.exploitability_score, v.impact_score, v.attack_vector,
                v.attack_complexity, v.privileges_required, v.user_interaction,
                v.primary_cwe, v.vuln_type, v.epss_score, v.epss_percentile,
                v.product_count, v.reference_count, v.kev_date_added, v.kev_vendor_project,
                v.kev_product, v.kev_notes, v.kev_required_action, v.kev_due_date
                
            ORDER BY
                v.published DESC NULLS LAST
            """
            
            # Execute the query and get the data
            df = pd.read_sql_query(query, conn)
            
            # Post-process the DataFrame to ensure data quality
            
            # 1. Convert boolean columns to proper boolean type
            bool_cols = ['known_exploited', 'has_exploit', 'has_cisa_advisory', 
                        'has_vendor_advisory', 'has_attack_mapping', 'remote_exploitable']
            for col in bool_cols:
                if col in df.columns:
                    df[col] = df[col].fillna(False).astype(bool)
            
            # 2. Ensure date columns are properly formatted
            date_cols = ['published', 'modified', 'kev_date_added', 'kev_due_date']
            for col in date_cols:
                if col in df.columns:
                    # Convert to datetime first to handle any format issues
                    df[col] = pd.to_datetime(df[col], errors='coerce')
                    # Then convert to string in a consistent format
                    df[col] = df[col].dt.strftime('%Y-%m-%d %H:%M:%S')
            
            # 3. Fill NaN values with appropriate defaults based on column type
            # For numeric columns, fill with 0
            numeric_cols = df.select_dtypes(include=['number']).columns
            df[numeric_cols] = df[numeric_cols].fillna(0)
            
            # For string columns, fill with empty string
            string_cols = df.select_dtypes(include=['object']).columns
            df[string_cols] = df[string_cols].fillna('')
            
            # 4. Create sample data for inspection 
            dir_path = os.path.dirname(output_path)
            os.makedirs(dir_path, exist_ok=True)
            
            sample_path = os.path.join(dir_path, 'classification_sample.csv')
            df.head(50).to_csv(sample_path, index=False)
            logger.info(f"Exported 50-record sample to {sample_path}")
            
            # 5. Save the full dataset
            df.to_csv(output_path, index=False)
            logger.info(f"Exported {len(df)} records to {output_path}")
            
            # 6. Also save a training subset if dataset is large
            if len(df) > 10000:
                training_path = os.path.join(dir_path, 'classification_training.csv')
                
                # Create a stratified sample by severity and vuln_type for balanced training
                try:
                    # Make sure we don't lose rare vulnerability classes
                    from sklearn.model_selection import train_test_split
                    
                    # Use a stratified sample if severity and vuln_type are available and have values
                    has_severity = 'severity' in df.columns and df['severity'].notna().any()
                    has_vuln_type = 'vuln_type' in df.columns and df['vuln_type'].notna().any()
                    
                    if has_severity and has_vuln_type:
                        # Create a combined stratification column
                        df['strat_temp'] = df['severity'].astype(str) + '_' + df['vuln_type'].astype(str)
                        train_df, _ = train_test_split(
                            df, train_size=10000, 
                            stratify=df['strat_temp'], 
                            random_state=42
                        )
                        # Remove the temporary column
                        train_df = train_df.drop(columns=['strat_temp'])
                    else:
                        # Just take a random sample otherwise
                        train_df = df.sample(10000, random_state=42)
                        
                    train_df.to_csv(training_path, index=False)
                    logger.info(f"Exported 10,000-record training dataset to {training_path}")
                    
                except Exception as e:
                    logger.warning(f"Could not create stratified training sample: {e}")
                    # Fallback to simple random sample
                    df.sample(min(10000, len(df)), random_state=42).to_csv(training_path, index=False)
                    logger.info(f"Exported random training dataset to {training_path}")
            
            return df
            
        except Exception as e:
            logger.error(f"Error exporting data to CSV: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return pd.DataFrame()  # Return empty DataFrame on error

    def _parse_date(self, date_str):
        """Parse date string into datetime object."""
        if not date_str:
            return None
            
        formats = [
            "%Y-%m-%dT%H:%M:%S.%fZ",  # ISO format with microseconds
            "%Y-%m-%dT%H:%M:%SZ",     # ISO format without microseconds
            "%Y-%m-%dT%H:%M:%S",      # ISO format without Z
            "%Y-%m-%d %H:%M:%S",      # Simple datetime
            "%Y-%m-%d",               # Just date
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(date_str, fmt)
            except ValueError:
                continue
        
        return None

    def get_all_cwe_entries(self):
        """
        Retrieve all CWE entries from the database.
        
        Returns:
            list: All CWE entries as a list of dictionaries
        """
        conn = self.connect()
        cursor = conn.cursor()
        
        try:
            # Query to get all CWE records with all relevant fields
            cursor.execute("""
                SELECT 
                    cwe_id, 
                    name, 
                    description, 
                    extended_description, 
                    abstraction, 
                    status, 
                    category,
                    relationships,
                    consequences,
                    mitigations,
                    likelihood,
                    data
                FROM weaknesses
                ORDER BY cwe_id
            """)
            
            # Fetch all records
            rows = cursor.fetchall()
            
            # Convert each row to a dictionary
            cwe_entries = []
            for row in rows:
                # Create a dictionary with all the fields
                cwe_entry = {
                    'cwe_id': row[0],
                    'name': row[1],
                    'description': row[2],
                    'extended_description': row[3],
                    'abstraction': row[4],
                    'status': row[5],
                    'category': row[6]
                }
                
                # Handle JSON fields that might be returned as strings
                for i, field_name in enumerate(['relationships', 'consequences', 'mitigations'], start=7):
                    if row[i]:
                        if isinstance(row[i], str):
                            try:
                                cwe_entry[field_name] = json.loads(row[i])
                            except json.JSONDecodeError:
                                cwe_entry[field_name] = row[i]
                        else:
                            cwe_entry[field_name] = row[i]
                    else:
                        cwe_entry[field_name] = {}
                
                # Add likelihood
                cwe_entry['likelihood'] = row[10]
                
                # Add the full data field if available, otherwise use the constructed entry
                if row[11]:
                    if isinstance(row[11], str):
                        try:
                            full_data = json.loads(row[11])
                            # Update with any additional fields not already in our basic entry
                            for k, v in full_data.items():
                                if k not in cwe_entry:
                                    cwe_entry[k] = v
                        except json.JSONDecodeError:
                            pass
                    elif isinstance(row[11], dict):
                        # Update with any additional fields not already in our basic entry
                        for k, v in row[11].items():
                            if k not in cwe_entry:
                                cwe_entry[k] = v
                
                cwe_entries.append(cwe_entry)
            
            logger.info(f"Retrieved {len(cwe_entries)} CWE entries from database")
            return cwe_entries
        
        except Exception as e:
            logger.error(f"Error retrieving CWE entries: {e}")
            return []
        
        finally:
            cursor.close()
    def clear_vulnerabilities(self):
        """Clear all vulnerability data from the database with improved connection handling."""
        # Get existing connection if available, otherwise create a new one
        if self.conn is not None and not self.conn.closed:
            conn = self.conn
            # Make sure we're not in a transaction already
            if conn.status == psycopg2.extensions.STATUS_IN_TRANSACTION:
                conn.rollback()
        else:
            conn = self.connect()
        
        # Set a timeout for operations
        cursor = conn.cursor()
        try:
            # Set statement timeout to prevent hanging (30 seconds)
            cursor.execute("SET statement_timeout = 30000")
            
            # Use TRUNCATE for faster deletion where possible
            logger.info("Clearing vulnerability data - this might take a moment...")
            
            # Delete data in batches for large tables if needed
            tables = [
                "vulnerability_products",
                "vulnerability_weaknesses",
                "vulnerability_attack_mappings",
                "vulnerability_capec_mappings",
                "metrics",
                "vuln_references"
            ]
            
            # First delete from related tables
            for table in tables:
                try:
                    # TRUNCATE is much faster than DELETE for clearing entire tables
                    cursor.execute(f"TRUNCATE TABLE {table} CASCADE")
                    conn.commit()  # Commit after each table to avoid long transactions
                    logger.info(f"Cleared table {table}")
                except Exception as e:
                    conn.rollback()
                    logger.warning(f"Error clearing table {table}: {e}")
                    # Fallback to standard DELETE
                    try:
                        cursor.execute(f"DELETE FROM {table}")
                        conn.commit()
                        logger.info(f"Cleared table {table} using DELETE")
                    except Exception as e2:
                        conn.rollback()
                        logger.error(f"Failed to clear table {table}: {e2}")
            
            # Finally delete the main vulnerabilities table
            try:
                cursor.execute("TRUNCATE TABLE vulnerabilities CASCADE")
                conn.commit()
                logger.info("Cleared vulnerabilities table")
            except Exception as e:
                conn.rollback()
                logger.warning(f"Error truncating vulnerabilities table: {e}")
                # If TRUNCATE fails, try batch DELETE
                try:
                    logger.info("Attempting batch deletion of vulnerabilities...")
                    # Delete in batches of 10,000
                    batch_size = 10000
                    total_deleted = 0
                    
                    while True:
                        cursor.execute(f"DELETE FROM vulnerabilities LIMIT {batch_size}")
                        deleted = cursor.rowcount
                        if deleted == 0:
                            break
                        total_deleted += deleted
                        conn.commit()
                        logger.info(f"Deleted {total_deleted} vulnerability records...")
                    
                    logger.info(f"Successfully deleted all {total_deleted} vulnerability records")
                except Exception as e2:
                    conn.rollback()
                    logger.error(f"Failed to delete vulnerability records: {e2}")
                    raise
            
            logger.info("All vulnerability data cleared from database")
            return True
        except Exception as e:
            conn.rollback()
            logger.error(f"Error clearing vulnerability data: {e}")
            raise
        finally:
            # Reset statement timeout
            try:
                cursor.execute("RESET statement_timeout")
                conn.commit()
            except:
                pass
            cursor.close()

    def _determine_vuln_type(self, cwe_ids):
        """Determine vulnerability type based on CWE IDs."""
        if not cwe_ids:
            return "Unknown"
        
        # Map common CWEs to vulnerability types
        cwe_type_map = {
            "CWE-79": "Cross-site Scripting",
            "CWE-89": "SQL Injection",
            "CWE-119": "Buffer Overflow",
            "CWE-120": "Buffer Overflow",
            "CWE-125": "Buffer Overflow",
            "CWE-200": "Information Disclosure",
            "CWE-264": "Access Control",
            "CWE-284": "Access Control",
            "CWE-287": "Authentication Issues",
            "CWE-20": "Input Validation",
            "CWE-352": "Cross-Site Request Forgery",
            "CWE-22": "Path Traversal",
            "CWE-94": "Code Injection",
            "CWE-78": "Command Injection",
            "CWE-502": "Deserialization",
            "CWE-416": "Use After Free",
            "CWE-476": "Null Pointer Dereference",
            "CWE-798": "Hardcoded Credentials",
            "CWE-295": "Certificate Validation",
            "CWE-400": "Resource Exhaustion",
            "CWE-116": "Improper Encoding/Escaping"
        }
        
        # Check each CWE in our list
        for cwe_id in cwe_ids:
            if cwe_id in cwe_type_map:
                return cwe_type_map[cwe_id]
        
        # If no specific match, use CWE number ranges to categorize
        try:
            # Try with the first CWE
            cwe_id = cwe_ids[0]
            if cwe_id.startswith("CWE-"):
                cwe_num = int(cwe_id[4:])
                
                # Use number ranges for common categories
                if 119 <= cwe_num <= 127:
                    return "Memory Safety"
                elif 74 <= cwe_num <= 94:
                    return "Injection"
                elif 264 <= cwe_num <= 286:
                    return "Access Control"
                elif 310 <= cwe_num <= 340:
                    return "Cryptographic Issues"
                elif 200 <= cwe_num <= 213:
                    return "Information Disclosure"
        except (ValueError, IndexError):
            pass
        
        return "Other"

        """
        Insert or update a CWE entry in the database.
        
        Args:
            cwe_entry: Dictionary containing CWE data
            
        Returns:
            bool: True if successful, False otherwise
        """
        conn = self.connect()
        cursor = conn.cursor()
        
        try:
            cwe_id = cwe_entry.get('cwe_id')
            if not cwe_id:
                logger.warning("CWE entry has no ID, skipping")
                return False
                
            # Extract fields from CWE entry
            name = cwe_entry.get('name', '')
            description = cwe_entry.get('description', '')
            extended_description = cwe_entry.get('extended_description', '')
            abstraction = cwe_entry.get('abstraction', '')
            status = cwe_entry.get('status', '')
            category = cwe_entry.get('category', '')
            likelihood = cwe_entry.get('likelihood', '')
            mitigations_text = cwe_entry.get('mitigations_text', '')
            
            # Convert remaining data to JSON
            # First, create a copy without the fields we've extracted
            data = {k: v for k, v in cwe_entry.items() if k not in 
                    ['cwe_id', 'name', 'description', 'extended_description',
                    'abstraction', 'status', 'category', 'likelihood', 'mitigations_text']}
            
            # Insert or update the CWE entry
            cursor.execute("""
                INSERT INTO weaknesses (
                    cwe_id, name, description, extended_description,
                    abstraction, status, category, likelihood,
                    mitigations_text, data
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (cwe_id) DO UPDATE SET
                    name = EXCLUDED.name,
                    description = EXCLUDED.description,
                    extended_description = EXCLUDED.extended_description,
                    abstraction = EXCLUDED.abstraction,
                    status = EXCLUDED.status,
                    category = EXCLUDED.category,
                    likelihood = EXCLUDED.likelihood,
                    mitigations_text = EXCLUDED.mitigations_text,
                    data = EXCLUDED.data
            """, (
                cwe_id, name, description, extended_description,
                abstraction, status, category, likelihood,
                mitigations_text, psycopg2.extras.Json(data) if data else None
            ))
            
            conn.commit()
            return True
            
        except Exception as e:
            conn.rollback()
            logger.error(f"Error inserting CWE {cwe_entry.get('cwe_id')}: {e}")
            return False
        finally:
            cursor.close()
    def insert_vulnerability(self, vuln):
        """Insert or update a vulnerability record with enhanced fields."""
        conn = self.connect()
        cursor = conn.cursor()
        
        try:
            # Extract primary fields
            vuln_id = vuln.get('id')
            if not vuln_id:
                logger.warning("Skipping vulnerability with no ID")
                return False
                
            description = vuln.get('description', '')
            
            # Extract dates - check multiple possible locations
            published = vuln.get('published')
            if not published:
                published = vuln.get('published_date')
                if not published:
                    published = vuln.get('other', {}).get('published')
            
            modified = vuln.get('modified')
            if not modified:
                modified = vuln.get('modified_date')
                if not modified:
                    modified = vuln.get('other', {}).get('modified')
                    
            # Parse dates if they're strings
            if published and isinstance(published, str):
                published = self._parse_date(published)
            if modified and isinstance(modified, str):
                modified = self._parse_date(modified)
            
            # Extract reporter and source
            reporter = vuln.get('reporter', '')
            source = vuln.get('other', {}).get('source', '')
            
            # Extract boolean fields
            known_exploited = vuln.get('known_exploited', False)
            has_exploit = vuln.get('has_exploit', False)
            
            # Check for CISA advisory in vulnrichment
            vulnrichment = vuln.get('vulnrichment', {})
            has_cisa_advisory = bool(vulnrichment.get('cisaKev', {}))
            
            # Check for vendor advisory in references
            has_vendor_advisory = False
            for ref in vuln.get('references', []):
                if isinstance(ref, dict) and 'Vendor Advisory' in ref.get('tags', []):
                    has_vendor_advisory = True
                    break
            
            # Extract CVSS data
            cvss = vuln.get('cvss', {})
            base_score = cvss.get('base_score')
            severity = cvss.get('base_severity', '')
            cvss_version = cvss.get('version', '')
            cvss_vector = cvss.get('vector', '')
            exploitability_score = cvss.get('exploitability_score')
            impact_score = cvss.get('impact_score')
            
            # Extract CVSS vector components
            attack_vector = cvss.get('attack_vector')
            attack_complexity = cvss.get('attack_complexity')
            privileges_required = cvss.get('privileges_required')
            user_interaction = cvss.get('user_interaction')
            
            # If direct fields aren't available, parse from vector string
            if cvss_vector and not all([attack_vector, attack_complexity, privileges_required, user_interaction]):
                # Parse from vector string like "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                if 'AV:N' in cvss_vector:
                    attack_vector = 'NETWORK'
                elif 'AV:A' in cvss_vector:
                    attack_vector = 'ADJACENT_NETWORK'
                elif 'AV:L' in cvss_vector:
                    attack_vector = 'LOCAL'
                elif 'AV:P' in cvss_vector:
                    attack_vector = 'PHYSICAL'
                    
                if 'AC:L' in cvss_vector:
                    attack_complexity = 'LOW'
                elif 'AC:H' in cvss_vector:
                    attack_complexity = 'HIGH'
                    
                if 'PR:N' in cvss_vector:
                    privileges_required = 'NONE'
                elif 'PR:L' in cvss_vector:
                    privileges_required = 'LOW'
                elif 'PR:H' in cvss_vector:
                    privileges_required = 'HIGH'
                    
                if 'UI:N' in cvss_vector:
                    user_interaction = 'NONE'
                elif 'UI:R' in cvss_vector:
                    user_interaction = 'REQUIRED'
            
            # Extract CWE information
            cwe_ids = vuln.get('cwe', [])
            primary_cwe = cwe_ids[0] if isinstance(cwe_ids, list) and cwe_ids else None
            
            # Determine vulnerability type based on CWE
            vuln_type = self._determine_vuln_type(cwe_ids)
            
            # Extract product and reference counts
            products = vuln.get('products', [])
            product_count = len(products)
            references = vuln.get('references', [])
            reference_count = len(references)
            
            # Extract EPSS data
            epss_score = vuln.get('epss_score')
            epss_percentile = vuln.get('epss_percentile')
            
            # Extract KEV data
            kev_fields = {}
            if vulnrichment and 'cisaKev' in vulnrichment:
                cisaKev = vulnrichment.get('cisaKev', {})
                kev_date_added = self._parse_date(cisaKev.get('dateAdded', ''))
                kev_vendor_project = cisaKev.get('vendorProject', '')
                kev_product = cisaKev.get('product', '')
                kev_notes = cisaKev.get('notes', '')
                kev_required_action = cisaKev.get('requiredAction', '')
                kev_due_date = self._parse_date(cisaKev.get('dueDate', ''))
            else:
                kev_date_added = None
                kev_vendor_project = ''
                kev_product = ''
                kev_notes = ''
                kev_required_action = ''
                kev_due_date = None
            
            # Check for patch information in references
            has_patch = False
            patch_date = None
            patch_references = []
            
            for ref in vuln.get('references', []):
                if isinstance(ref, dict):
                    # Look for patch-related tags
                    tags = ref.get('tags', [])
                    if any(tag in ['Patch', 'Vendor Advisory', 'Issue Tracking', 'Fix'] for tag in tags):
                        has_patch = True
                        # Use reference date if available
                        if 'url_date' in ref:
                            if patch_date is None or ref['url_date'] < patch_date:
                                patch_date = ref['url_date']
                        patch_references.append(ref.get('url', ''))
            
            # If no specific patch date found, use modified date
            if has_patch and not patch_date and vuln.get('modified'):
                patch_date = vuln.get('modified')
            
            # Calculate days to patch
            days_to_patch = None
            if has_patch and patch_date and vuln.get('published'):
                try:
                    pub_date = self._parse_date(vuln.get('published'))
                    p_date = self._parse_date(patch_date)
                    if pub_date and p_date:
                        days_to_patch = (p_date - pub_date).days
                except:
                    pass

            # Extract and store mitigation information from references
            mitigation_info = []
            for ref in vuln.get('references', []):
                if isinstance(ref, dict):
                    tags = ref.get('tags', [])
                    if any(tag in ['Mitigation', 'Vendor Advisory', 'Solution'] for tag in tags):
                        mitigation_info.append({
                            'url': ref.get('url', ''),
                            'source': ref.get('source', ''),
                            'tags': tags
                        })

            # Extract mitigation descriptions from CWEs
            cwe_mitigations = []
            for cwe_id in cwe_ids:
                cursor.execute("SELECT mitigations_text FROM weaknesses WHERE cwe_id = %s", (cwe_id,))
                result = cursor.fetchone()
                if result and result[0]:
                    cwe_mitigations.append({
                        'cwe_id': cwe_id,
                        'mitigation': result[0]
                    })

            # Add mitigation information to the vulnerability record if available
            if mitigation_info or cwe_mitigations:
                mitigation_data = {
                    'has_mitigation': True,
                    'reference_mitigations': mitigation_info,
                    'cwe_mitigations': cwe_mitigations
                }
                
                # Store mitigation data in a new column or in the data JSONB field
                if isinstance(vuln, dict):
                    vuln['mitigation_data'] = mitigation_data
            
            # Insert or update vulnerability with all fields
            cursor.execute("""
                INSERT INTO vulnerabilities (
                    id, description, published, modified, reporter, source,
                    known_exploited, has_exploit, has_cisa_advisory, has_vendor_advisory,
                    base_score, severity, cvss_version, cvss_vector, exploitability_score, impact_score,
                    attack_vector, attack_complexity, privileges_required, user_interaction,
                    primary_cwe, vuln_type, product_count, reference_count,
                    epss_score, epss_percentile,
                    kev_date_added, kev_vendor_project, kev_product, kev_notes, kev_required_action, kev_due_date,
                    has_patch, patch_date, days_to_patch, patch_references,
                    data
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO UPDATE SET
                    description = EXCLUDED.description,
                    published = EXCLUDED.published,
                    modified = EXCLUDED.modified,
                    reporter = EXCLUDED.reporter,
                    source = EXCLUDED.source,
                    known_exploited = EXCLUDED.known_exploited,
                    has_exploit = EXCLUDED.has_exploit,
                    has_cisa_advisory = EXCLUDED.has_cisa_advisory,
                    has_vendor_advisory = EXCLUDED.has_vendor_advisory,
                    base_score = EXCLUDED.base_score,
                    severity = EXCLUDED.severity,
                    cvss_version = EXCLUDED.cvss_version,
                    cvss_vector = EXCLUDED.cvss_vector,
                    exploitability_score = EXCLUDED.exploitability_score,
                    impact_score = EXCLUDED.impact_score,
                    attack_vector = EXCLUDED.attack_vector,
                    attack_complexity = EXCLUDED.attack_complexity,
                    privileges_required = EXCLUDED.privileges_required,
                    user_interaction = EXCLUDED.user_interaction,
                    primary_cwe = EXCLUDED.primary_cwe,
                    vuln_type = EXCLUDED.vuln_type,
                    product_count = EXCLUDED.product_count,
                    reference_count = EXCLUDED.reference_count,
                    epss_score = EXCLUDED.epss_score,
                    epss_percentile = EXCLUDED.epss_percentile,
                    kev_date_added = EXCLUDED.kev_date_added,
                    kev_vendor_project = EXCLUDED.kev_vendor_project,
                    kev_product = EXCLUDED.kev_product,
                    kev_notes = EXCLUDED.kev_notes,
                    kev_required_action = EXCLUDED.kev_required_action,
                    kev_due_date = EXCLUDED.kev_due_date,
                    has_patch = EXCLUDED.has_patch,
                    patch_date = EXCLUDED.patch_date,
                    days_to_patch = EXCLUDED.days_to_patch,
                    patch_references = EXCLUDED.patch_references,
                    data = EXCLUDED.data
            """, (
                vuln_id, description, published, modified, reporter, source,
                known_exploited, has_exploit, has_cisa_advisory, has_vendor_advisory,
                base_score, severity, cvss_version, cvss_vector, exploitability_score, impact_score,
                attack_vector, attack_complexity, privileges_required, user_interaction,
                primary_cwe, vuln_type, product_count, reference_count,
                epss_score, epss_percentile,
                kev_date_added, kev_vendor_project, kev_product, kev_notes, kev_required_action, kev_due_date,
                has_patch, patch_date, days_to_patch, Json(patch_references) if patch_references else None,
                Json(vuln)
            ))
            
            # Insert products
            product_ids = []
            for product in products:
                vendor = product.get('vendor', '')
                product_name = product.get('product', '')
                version = product.get('version', '')
                
                cursor.execute("""
                    INSERT INTO products (vendor, product, version)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (vendor, product, version) DO UPDATE SET
                    vendor = EXCLUDED.vendor
                    RETURNING id
                """, (vendor, product_name, version))
                
                product_id = cursor.fetchone()[0]
                product_ids.append(product_id)
            
            # Link products to vulnerability
            for product_id in product_ids:
                cursor.execute("""
                    INSERT INTO vulnerability_products (vuln_id, product_id)
                    VALUES (%s, %s)
                    ON CONFLICT (vuln_id, product_id) DO NOTHING
                """, (vuln_id, product_id))
            
            # Insert CWE weaknesses - check if CWE exists first or add it
            for cwe in cwe_ids:
                if cwe:
                    # First check if this CWE exists in the weaknesses table
                    cursor.execute("SELECT COUNT(*) FROM weaknesses WHERE cwe_id = %s", (cwe,))
                    if cursor.fetchone()[0] == 0:
                        # CWE doesn't exist - create a placeholder entry
                        try:
                            cursor.execute("""
                                INSERT INTO weaknesses (cwe_id, name, description)
                                VALUES (%s, %s, %s)
                                ON CONFLICT (cwe_id) DO NOTHING
                            """, (cwe, f"Auto-generated placeholder for {cwe}", f"Placeholder for {cwe} - will be updated when full CWE data is processed"))
                        except Exception as e:
                            logger.warning(f"Could not create placeholder for CWE {cwe}: {e}")
                            continue
                    
                    # Now insert the mapping
                    try:
                        cursor.execute("""
                            INSERT INTO vulnerability_weaknesses (vuln_id, cwe_id)
                            VALUES (%s, %s)
                            ON CONFLICT (vuln_id, cwe_id) DO NOTHING
                        """, (vuln_id, cwe))
                    except Exception as e:
                        logger.warning(f"Could not map {vuln_id} to {cwe}: {e}")
            
            # Insert CVSS metrics
            if cvss:
                # Change from ON CONFLICT (vuln_id) to ON CONFLICT DO NOTHING since there's no unique constraint defined
                cursor.execute("""
                    INSERT INTO metrics (vuln_id, cvss_version, base_score, vector, exploitability_score, impact_score, data)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT DO NOTHING
                """, (vuln_id, cvss_version, base_score, cvss_vector, exploitability_score, impact_score, Json(cvss)))
            
            # Insert references - Use ON CONFLICT DO NOTHING without specifying columns
            for ref in references:
                if isinstance(ref, str):
                    url = ref
                    source = ''
                    tags = []
                else:
                    url = ref.get('url', '')
                    source = ref.get('source', '')
                    tags = ref.get('tags', [])
                
                cursor.execute("""
                    INSERT INTO vuln_references (vuln_id, url, source, tags)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT DO NOTHING
                """, (vuln_id, url, source, Json(tags)))
            
            conn.commit()
            return True
        except Exception as e:
            conn.rollback()
            logger.error(f"Error inserting vulnerability {vuln.get('id')}: {e}")
            return False
        finally:
            cursor.close()