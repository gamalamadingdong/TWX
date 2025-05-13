import os
import sys

# Add project root to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from storage.vulnerability_db import VulnerabilityDatabase

def export_classification_data():
    print("Exporting classification data from database...")
    db = VulnerabilityDatabase(create_tables=False)
    
    # Export to CSV
    output_path = "analysis/classification_data.csv"
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    # Call the export function
    db.export_to_csv(output_path)
    
    print(f"Classification data successfully exported to {output_path}")

if __name__ == "__main__":
    export_classification_data()