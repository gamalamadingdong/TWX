import os
import subprocess
import logging
from datetime import datetime
import pandas as pd
import psycopg2

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def export_postgresql_schema(output_dir="documentation", 
                             db_name=None, 
                             user=None, 
                             password=None, 
                             host=None, 
                             port=None,
                             pg_bin_path=None):
    """
    Export the PostgreSQL database schema to SQL files.
    
    Args:
        output_dir: Directory to save the schema files
        db_name: Database name (defaults to env var TWX_DB_NAME or "twx")
        user: PostgreSQL username (defaults to env var TWX_DB_USER or "postgres")
        password: PostgreSQL password (defaults to env var TWX_DB_PASSWORD)
        host: PostgreSQL host (defaults to env var TWX_DB_HOST or "localhost")
        port: PostgreSQL port (defaults to env var TWX_DB_PORT or "5432")
        pg_bin_path: Path to PostgreSQL bin directory containing pg_dump and psql
    
    Returns:
        bool: True if export was successful, False otherwise
    """
    # Get connection parameters from environment variables or use defaults
    db_name = db_name or os.environ.get('TWX_DB_NAME', 'twx')
    user = user or os.environ.get('TWX_DB_USER', 'postgres')
    password = password or os.environ.get('TWX_DB_PASSWORD', '')
    host = host or os.environ.get('TWX_DB_HOST', 'localhost')
    port = port or os.environ.get('TWX_DB_PORT', '5432')
    
    # Check for PostgreSQL bin path or use common installation locations
    if not pg_bin_path:
        # Common installation locations on Windows
        common_paths = [
            r"C:\Program Files\PostgreSQL\16\bin",
            r"C:\Program Files\PostgreSQL\15\bin",
            r"C:\Program Files\PostgreSQL\14\bin",
            r"C:\Program Files\PostgreSQL\13\bin",
            r"C:\Program Files\PostgreSQL\12\bin",
            # Add more paths as needed
        ]
        
        # Try to find PostgreSQL binaries
        for path in common_paths:
            if os.path.exists(os.path.join(path, "pg_dump.exe")):
                pg_bin_path = path
                logger.info(f"Found PostgreSQL tools at: {pg_bin_path}")
                break
    
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Generate filenames
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    schema_file = os.path.join(output_dir, f"db_schema_{timestamp}.sql")
    table_list_file = os.path.join(output_dir, f"table_list_{timestamp}.txt")
    detailed_schema_file = os.path.join(output_dir, f"detailed_schema_{timestamp}.sql")
    
    # Check if we can use command-line tools or need to fall back to direct connection
    use_cli_tools = True
    if pg_bin_path:
        pg_dump_path = os.path.join(pg_bin_path, "pg_dump")
        psql_path = os.path.join(pg_bin_path, "psql")
    else:
        if os.system("pg_dump --version > nul 2>&1") != 0:
            logger.warning("PostgreSQL command-line tools not found in PATH or specified locations")
            logger.info("Falling back to direct database connection")
            use_cli_tools = False
        else:
            pg_dump_path = "pg_dump"
            psql_path = "psql"
    
    try:
        # Set PGPASSWORD environment variable for passwordless connection
        pg_env = os.environ.copy()
        if password:
            pg_env['PGPASSWORD'] = password
        
        if use_cli_tools:
            # Export schema using pg_dump
            logger.info(f"Exporting schema to {schema_file}...")
            schema_cmd = [
                pg_dump_path, 
                '--host', host,
                '--port', port,
                '--username', user,
                '--dbname', db_name,
                '--schema-only',
                '--no-owner',
                '--file', schema_file
            ]
            
            # For debugging, show the exact command being run
            logger.info(f"Running command: {' '.join(schema_cmd)}")
            subprocess.run(schema_cmd, env=pg_env, check=True)
            
            # Continue with the rest of the CLI-based export...
            # [rest of your existing code using psql_path]
            
        else:
            # ALTERNATIVE APPROACH: Use direct database connection
            logger.info("Using direct database connection to export schema")
            conn = psycopg2.connect(
                dbname=db_name,
                user=user,
                password=password,
                host=host,
                port=port
            )
            
            # Export table list
            logger.info(f"Generating table list to {table_list_file}...")
            with open(table_list_file, 'w') as f:
                f.write("# TWX Database Tables\n\n")
                f.write("| Table Name | Description |\n")
                f.write("|------------|-------------|\n")
                
                # Query tables
                tables_df = pd.read_sql("SELECT table_name FROM information_schema.tables WHERE table_schema='public' ORDER BY table_name", conn)
                for table_name in tables_df['table_name']:
                    f.write(f"| {table_name} | |\n")
            
            # Generate detailed schema
            logger.info(f"Generating detailed schema to {detailed_schema_file}...")
            with open(detailed_schema_file, 'w') as f:
                f.write("-- TWX Database Detailed Schema\n")
                f.write(f"-- Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                # Get table list
                tables_df = pd.read_sql("SELECT table_name FROM information_schema.tables WHERE table_schema='public' ORDER BY table_name", conn)
                
                # For each table, get and write column information
                for table_name in tables_df['table_name']:
                    f.write(f"\n-- Table: {table_name}\n")
                    f.write(f"CREATE TABLE IF NOT EXISTS {table_name} (\n")
                    
                    # Get column information
                    columns_df = pd.read_sql(f"""
                        SELECT column_name, data_type, character_maximum_length, is_nullable 
                        FROM information_schema.columns 
                        WHERE table_name = '{table_name}' 
                        ORDER BY ordinal_position
                    """, conn)
                    
                    # Format column definitions
                    column_defs = []
                    for _, row in columns_df.iterrows():
                        col_def = f"    {row['column_name']} {row['data_type']}"
                        if pd.notna(row['character_maximum_length']):
                            col_def += f"({int(row['character_maximum_length'])})"
                        if row['is_nullable'] == 'NO':
                            col_def += " NOT NULL"
                        column_defs.append(col_def)
                    
                    f.write(',\n'.join(column_defs))
                    f.write("\n);\n")
                    
                    # Get indexes
                    indexes_df = pd.read_sql(f"""
                        SELECT indexname, indexdef 
                        FROM pg_indexes 
                        WHERE tablename = '{table_name}'
                    """, conn)
                    
                    if not indexes_df.empty:
                        f.write("\n-- Indexes\n")
                        for _, row in indexes_df.iterrows():
                            f.write(f"{row['indexdef']};\n")
            
            conn.close()
            
            # Generate schema SQL file using pg_dump output data
            logger.info(f"Writing schema to {schema_file}...")
            with open(schema_file, 'w') as f:
                f.write("-- Schema generated from database connection\n")
                f.write(f"-- Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                # Write a comment indicating this was generated via database connection
                f.write("-- Note: This schema was generated via direct database connection\n")
                f.write("-- rather than pg_dump due to command-line tools being unavailable.\n\n")
                
                # Include the contents from detailed schema
                with open(detailed_schema_file, 'r') as detailed_f:
                    # Skip the first few lines which are headers
                    lines = detailed_f.readlines()[3:]  # Skip header lines
                    f.writelines(lines)
        
        logger.info("Schema export completed successfully")
        return True
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Error executing PostgreSQL command: {e}")
        if e.stderr:
            logger.error(f"Error details: {e.stderr}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error exporting schema: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return False

if __name__ == "__main__":
    import sys
    
    # Check for command line arguments
    if len(sys.argv) > 1:
        pg_bin_path = sys.argv[1]
        logger.info(f"Using PostgreSQL bin path from command line: {pg_bin_path}")
        export_postgresql_schema(pg_bin_path=pg_bin_path)
    else:
        export_postgresql_schema()