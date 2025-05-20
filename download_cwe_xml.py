import os
import requests
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def download_cwe_xml(output_path="data_collection/raw_data/cwe_data/cwec_v4.13.xml"):
    """
    Download the latest CWE XML file.
    """
    url = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
    
    logger.info(f"Downloading CWE XML from {url}")
    
    try:
        # Create output directory
        Path(os.path.dirname(output_path)).mkdir(parents=True, exist_ok=True)
        
        # Download ZIP file
        import requests
        response = requests.get(url)
        response.raise_for_status()
        
        # Save to temporary ZIP file
        zip_path = output_path + ".zip"
        with open(zip_path, 'wb') as f:
            f.write(response.content)
        
        logger.info(f"Downloaded ZIP file to {zip_path}")
        
        # Extract XML
        import zipfile
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            xml_files = [f for f in zip_ref.namelist() if f.endswith('.xml')]
            if xml_files:
                zip_ref.extract(xml_files[0], os.path.dirname(output_path))
                # Rename if needed
                extracted_path = os.path.join(os.path.dirname(output_path), xml_files[0])
                if extracted_path != output_path:
                    os.rename(extracted_path, output_path)
                
        logger.info(f"Extracted XML file to {output_path}")
        
        # Clean up ZIP file
        os.remove(zip_path)
        
        return True
        
    except Exception as e:
        logger.error(f"Error downloading CWE XML: {e}")
        return False

if __name__ == "__main__":
    download_cwe_xml()