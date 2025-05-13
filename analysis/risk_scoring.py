import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import os
import sys

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from storage.vulnerability_db import VulnerabilityDatabase

def calculate_csf_risk_score(vuln_data):
    """
    Calculate a risk score based on NIST Cybersecurity Framework categories.
    
    The score considers:
    - Identify: Does the vulnerability expose sensitive identifiers?
    - Protect: How difficult is it to protect against?
    - Detect: How easily can exploitation be detected?
    - Respond: How quickly can organizations respond?
    - Recover: How much effort is required to recover?
    
    Each category is scored 1-10, and the final score is a weighted average.
    """
    # Extract relevant features
    cvss = vuln_data.get('cvss', {})
    base_score = cvss.get('base_score', 5.0)
    vector = cvss.get('vector', '')
    
    # Default scores (mid-range)
    identify = 5
    protect = 5
    detect = 5
    respond = 5
    recover = 5
    
    # Adjust based on CVSS vector components
    if 'AV:N' in vector:  # Network attack vector
        identify += 2
        protect += 1
    if 'AC:L' in vector:  # Low attack complexity
        protect += 2
    if 'PR:N' in vector:  # No privileges required
        protect += 2
    if 'UI:N' in vector:  # No user interaction
        detect += 1
    if 'S:C' in vector:  # Changed scope
        recover += 2
    
    # Adjust based on impact components
    if 'C:H' in vector:  # High confidentiality impact
        identify += 2
        respond += 1
    if 'I:H' in vector:  # High integrity impact
        respond += 2
        recover += 2
    if 'A:H' in vector:  # High availability impact
        respond += 1
        recover += 3
    
    # Is it known to be exploited?
    if vuln_data.get('known_exploited', False):
        identify += 3
        protect += 2
        detect += 1
        respond += 2
        recover += 1
    
    # Cap scores at 10
    identify = min(10, identify)
    protect = min(10, protect)
    detect = min(10, detect)
    respond = min(10, respond)
    recover = min(10, recover)
    
    # Calculate weighted score (weights sum to 1)
    csf_score = (0.2 * identify + 0.3 * protect + 0.2 * detect + 
                 0.15 * respond + 0.15 * recover)
    
    return {
        'csf_score': csf_score,
        'components': {
            'identify': identify,
            'protect': protect,
            'detect': detect,
            'respond': respond, 
            'recover': recover
        }
    }

def calculate_fair_risk_score(vuln_data):
    """
    Calculate a risk score based on FAIR (Factor Analysis of Information Risk).
    
    FAIR focuses on:
    - Loss Event Frequency (LEF): How often might the vulnerability be exploited?
    - Loss Magnitude (LM): What's the potential impact if exploited?
    
    Risk = LEF * LM
    """
    # Extract relevant features
    cvss = vuln_data.get('cvss', {})
    base_score = cvss.get('base_score', 5.0)
    exploitability = cvss.get('exploitability_score', base_score/2)
    impact = cvss.get('impact_score', base_score/2)
    
    # Calculate Loss Event Frequency (scale 1-10)
    # Based on exploitability, known exploitation, and attack complexity
    lef_base = exploitability * 1.5  # Scale CVSS exploitability to 0-10
    
    # Adjust for known exploitation
    if vuln_data.get('known_exploited', False):
        lef_base += 2
    
    # Cap at 10
    lef = min(10, lef_base)
    
    # Calculate Loss Magnitude (scale 1-10)
    # Based on impact score and affected services
    lm_base = impact * 1.5  # Scale CVSS impact to 0-10
    
    # Adjust for number of affected products
    product_count = len(vuln_data.get('products', []))
    lm_adjustment = min(3, product_count / 3)  # Up to +3 based on affected products
    lm_base += lm_adjustment
    
    # Cap at 10
    lm = min(10, lm_base)
    
    # Calculate risk (scale 1-100)
    fair_risk = lef * lm
    
    return {
        'fair_risk': fair_risk,
        'components': {
            'loss_event_frequency': lef,
            'loss_magnitude': lm
        }
    }

def analyze_risk_scores():
    """Analyze vulnerability data using CSF and FAIR risk scoring models."""
    # Initialize database connection
    db = VulnerabilityDatabase()
    
    # Get vulnerability data
    vuln_ids = db.get_all_vulnerability_ids()
    
    # Calculate risk scores
    results = []
    for vuln_id in vuln_ids[:100]:  # Limit to 100 for demonstration
        vuln_data = db.get_vulnerability_by_id(vuln_id)
        
        if not vuln_data:
            continue
        
        # Calculate risk scores
        csf = calculate_csf_risk_score(vuln_data)
        fair = calculate_fair_risk_score(vuln_data)
        
        # Map to vulnerability type
        vuln_type = "Unknown"
        if 'cwe' in vuln_data and vuln_data['cwe']:
            from models.vuln_classifier import map_cwe_to_vuln_type
            vuln_type = map_cwe_to_vuln_type(vuln_data['cwe'][0])
        
        # Store results
        results.append({
            'id': vuln_id,
            'type': vuln_type,
            'cvss_score': vuln_data.get('cvss', {}).get('base_score', 0),
            'csf_score': csf['csf_score'],
            'fair_risk': fair['fair_risk'],
            'known_exploited': vuln_data.get('known_exploited', False),
        })
    
    # Convert to DataFrame
    df = pd.DataFrame(results)
    
    # Visualize risk scores by vulnerability type
    plt.figure(figsize=(12, 8))
    
    # Group by type and calculate mean scores
    type_risks = df.groupby('type').agg({
        'cvss_score': 'mean',
        'csf_score': 'mean',
        'fair_risk': 'mean',
        'id': 'count'  # Count of vulnerabilities
    }).sort_values('fair_risk', ascending=False).head(10)
    
    # Create grouped bar chart
    type_risks = type_risks.reset_index()
    fig, ax = plt.subplots(figsize=(14, 8))
    
    x = np.arange(len(type_risks))
    width = 0.25
    
    # Plot bars
    ax.bar(x - width, type_risks['cvss_score'], width, label='CVSS Score', color='skyblue')
    ax.bar(x, type_risks['csf_score'], width, label='CSF Score', color='lightgreen')
    ax.bar(x + width, type_risks['fair_risk']/10, width, label='FAIR Risk Score (÷10)', color='salmon')
    
    # Customize chart
    ax.set_ylabel('Risk Score')
    ax.set_title('Risk Scores by Vulnerability Type')
    ax.set_xticks(x)
    ax.set_xticklabels(type_risks['type'], rotation=45, ha='right')
    ax.legend()
    plt.tight_layout()
    
    # Save figure
    os.makedirs("analysis/figures", exist_ok=True)
    plt.savefig("analysis/figures/risk_scores_by_type.png")
    plt.close()
    
    # Display numerical results
    print("\nRisk Analysis by Vulnerability Type:")
    print(type_risks[['type', 'cvss_score', 'csf_score', 'fair_risk', 'id']].rename(
        columns={'id': 'count'}))
    
    # Save results
    df.to_csv("analysis/risk_scores.csv", index=False)
    print("Risk scores saved to analysis/risk_scores.csv")
    
    # Close database connection
    db.close()
    
    return df

# Add this method to VulnerabilityDatabase class
def get_all_vulnerability_ids(self):
    """Get all vulnerability IDs from the database."""
    conn = self.connect()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM vulnerabilities")
    ids = [row[0] for row in cursor.fetchall()]
    return ids

# Monkey patch the method into the class
VulnerabilityDatabase.get_all_vulnerability_ids = get_all_vulnerability_ids

if __name__ == "__main__":
    analyze_risk_scores()