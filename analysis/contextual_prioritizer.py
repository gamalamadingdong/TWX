"""
Context-Aware Vulnerability Prioritizer
Extends risk matrix with environment-specific scoring
"""

import pandas as pd
import numpy as np
from typing import Dict, List, Optional, Tuple
import json
from datetime import datetime, timedelta
import os
import sys

# Add the project root directory to Python path
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(root_dir)

from storage.postgresql_db import PostgresqlVulnerabilityDatabase
from analysis.advanced_vulnerability_analysis import VulnerabilityAnalyzer


class ContextualPrioritizer:
    """
    Extends basic vulnerability analysis with context-aware prioritization.
    
    This class takes into account:
    - Asset criticality and business impact
    - Network exposure levels
    - Actual exploit availability
    - Patch complexity and operational constraints
    - Temporal factors (how long vulnerabilities have been known)
    """
    
    def __init__(self, analyzer: Optional[VulnerabilityAnalyzer] = None):
        """Initialize with an existing analyzer or create a new one."""
        self.analyzer = analyzer or VulnerabilityAnalyzer()
        self.db = PostgresqlVulnerabilityDatabase()
        
    def prioritize_for_environment(self, 
                                 asset_inventory: pd.DataFrame,
                                 business_criticality: Dict[str, float],
                                 network_exposure: Dict[str, str],
                                 operational_constraints: Optional[Dict] = None) -> pd.DataFrame:
        """
        Generate prioritized vulnerability list for a specific environment.
        
        Args:
            asset_inventory: DataFrame with columns [asset_id, vendor, product, version, asset_type]
            business_criticality: Dict mapping asset_id to criticality score (0-1)
            network_exposure: Dict mapping asset_id to exposure level ('internal', 'dmz', 'internet')
            operational_constraints: Optional dict with maintenance windows, patch testing requirements
            
        Returns:
            DataFrame with prioritized vulnerabilities including contextual risk scores
        """
        # Get base vulnerability data
        vuln_data = self._get_relevant_vulnerabilities(asset_inventory)
        
        # Calculate base risk scores if not already present
        if 'risk_score' not in vuln_data.columns:
            vuln_data = self._calculate_base_risk_scores(vuln_data)
        
        # Apply contextual multipliers
        vuln_data = self._apply_criticality_multiplier(vuln_data, asset_inventory, business_criticality)
        vuln_data = self._apply_exposure_multiplier(vuln_data, asset_inventory, network_exposure)
        vuln_data = self._apply_exploit_availability_multiplier(vuln_data)
        vuln_data = self._apply_temporal_scoring(vuln_data)
        
        # Calculate final contextual risk score
        vuln_data['contextual_risk_score'] = (
            vuln_data['base_risk_score'] * 
            vuln_data['criticality_multiplier'] * 
            vuln_data['exposure_multiplier'] * 
            vuln_data['exploit_multiplier'] * 
            vuln_data['temporal_multiplier']
        )
        
        # Add remediation complexity if operational constraints provided
        if operational_constraints:
            vuln_data = self._calculate_remediation_complexity(vuln_data, operational_constraints)
            
        # Sort by contextual risk score
        vuln_data = vuln_data.sort_values('contextual_risk_score', ascending=False)
        
        # Add priority tiers
        vuln_data['priority_tier'] = pd.qcut(
            vuln_data['contextual_risk_score'], 
            q=[0, 0.7, 0.9, 0.95, 1.0], 
            labels=['Low', 'Medium', 'High', 'Critical']
        )
        
        return vuln_data
    
    def _get_relevant_vulnerabilities(self, asset_inventory: pd.DataFrame) -> pd.DataFrame:
        """Get vulnerabilities that affect assets in the inventory."""
        # Query database for vulnerabilities affecting these products
        relevant_vulns = []
        
        for _, asset in asset_inventory.iterrows():
            # Query vulnerabilities for this vendor/product/version combo
            query = """
            SELECT DISTINCT v.*, vp.product_id
            FROM vulnerabilities v
            JOIN vulnerability_products vp ON v.id = vp.vuln_id
            JOIN products p ON vp.product_id = p.id
            WHERE LOWER(p.vendor) LIKE LOWER(?)
            AND LOWER(p.product) LIKE LOWER(?)
            """
            
            results = self.db.execute_query(
                query, 
                (f"%{asset['vendor']}%", f"%{asset['product']}%")
            )
            
            for vuln in results:
                vuln_dict = dict(vuln)
                vuln_dict['asset_id'] = asset['asset_id']
                relevant_vulns.append(vuln_dict)
        
        return pd.DataFrame(relevant_vulns)
    
    def _calculate_base_risk_scores(self, vuln_data: pd.DataFrame) -> pd.DataFrame:
        """Calculate base risk scores using CVSS and other metrics."""
        # Base risk = CVSS base score * impact factor
        vuln_data['base_risk_score'] = vuln_data['base_score'].fillna(5.0)
        
        # Boost score if exploit is known
        vuln_data.loc[vuln_data['known_exploited'] == True, 'base_risk_score'] *= 1.5
        
        # Normalize to 0-10 scale
        vuln_data['base_risk_score'] = vuln_data['base_risk_score'].clip(0, 10)
        
        return vuln_data
    
    def _apply_criticality_multiplier(self, vuln_data: pd.DataFrame, 
                                    asset_inventory: pd.DataFrame,
                                    business_criticality: Dict[str, float]) -> pd.DataFrame:
        """Apply business criticality multiplier to vulnerabilities."""
        # Merge criticality scores
        asset_crit = pd.DataFrame([
            {'asset_id': k, 'criticality': v} 
            for k, v in business_criticality.items()
        ])
        
        vuln_data = vuln_data.merge(asset_crit, on='asset_id', how='left')
        
        # Convert criticality (0-1) to multiplier (0.5-2.0)
        vuln_data['criticality_multiplier'] = 0.5 + (vuln_data['criticality'].fillna(0.5) * 1.5)
        
        return vuln_data
    
    def _apply_exposure_multiplier(self, vuln_data: pd.DataFrame,
                                  asset_inventory: pd.DataFrame,
                                  network_exposure: Dict[str, str]) -> pd.DataFrame:
        """Apply network exposure multiplier."""
        exposure_scores = {
            'internal': 0.5,
            'dmz': 1.0,
            'internet': 2.0
        }
        
        # Create exposure dataframe
        asset_exposure = pd.DataFrame([
            {'asset_id': k, 'exposure': v} 
            for k, v in network_exposure.items()
        ])
        
        vuln_data = vuln_data.merge(asset_exposure, on='asset_id', how='left')
        
        # Map exposure to multiplier
        vuln_data['exposure_multiplier'] = vuln_data['exposure'].map(exposure_scores).fillna(1.0)
        
        # Further adjust based on attack vector
        # Remote vulnerabilities on internet-facing assets get extra weight
        remote_internet = (
            (vuln_data['attack_vector'] == 'NETWORK') & 
            (vuln_data['exposure'] == 'internet')
        )
        vuln_data.loc[remote_internet, 'exposure_multiplier'] *= 1.5
        
        return vuln_data
    
    def _apply_exploit_availability_multiplier(self, vuln_data: pd.DataFrame) -> pd.DataFrame:
        """Apply multiplier based on exploit availability and usage."""
        # Start with base multiplier
        vuln_data['exploit_multiplier'] = 1.0
        
        # Known exploited (KEV list) - highest priority
        vuln_data.loc[vuln_data['known_exploited'] == True, 'exploit_multiplier'] = 2.0
        
        # Has exploit code available
        vuln_data.loc[vuln_data['has_exploit'] == True, 'exploit_multiplier'] = 1.5
        
        # High EPSS score (if available)
        if 'epss_score' in vuln_data.columns:
            high_epss = vuln_data['epss_score'] > 0.5
            vuln_data.loc[high_epss, 'exploit_multiplier'] = vuln_data.loc[high_epss, 'exploit_multiplier'] * 1.3
        
        return vuln_data
    
    def _apply_temporal_scoring(self, vuln_data: pd.DataFrame) -> pd.DataFrame:
        """Apply temporal scoring based on vulnerability age and trends."""
        # Newer vulnerabilities might get more attention from attackers
        current_date = pd.Timestamp.now()
        
        if 'published' in vuln_data.columns:
            vuln_data['published'] = pd.to_datetime(vuln_data['published'])
            vuln_data['days_since_published'] = (vuln_data['published'] - current_date).dt.days.abs()
            
            # Recent vulnerabilities (< 30 days) get a boost
            # Old unpatched vulnerabilities (> 1 year) also get a boost
            vuln_data['temporal_multiplier'] = 1.0
            
            # Recent vulnerabilities
            recent = vuln_data['days_since_published'] < 30
            vuln_data.loc[recent, 'temporal_multiplier'] = 1.3
            
            # Old unpatched vulnerabilities
            old_unpatched = vuln_data['days_since_published'] > 365
            vuln_data.loc[old_unpatched, 'temporal_multiplier'] = 1.2
        else:
            vuln_data['temporal_multiplier'] = 1.0
            
        return vuln_data
    
    def _calculate_remediation_complexity(self, vuln_data: pd.DataFrame, 
                                        operational_constraints: Dict) -> pd.DataFrame:
        """Calculate how complex it will be to remediate each vulnerability."""
        # Factors: patch availability, downtime required, testing needs
        vuln_data['remediation_complexity'] = 'Medium'
        
        # Check maintenance windows
        if 'maintenance_windows' in operational_constraints:
            # Assets with rare maintenance windows have higher complexity
            vuln_data['remediation_complexity'] = 'High'
            
        # Check if patches require reboots (simplified logic)
        if 'requires_reboot' in vuln_data.columns:
            vuln_data.loc[vuln_data['requires_reboot'] == True, 'remediation_complexity'] = 'High'
            
        return vuln_data
    
    def generate_remediation_plan(self, prioritized_vulns: pd.DataFrame,
                                max_vulns_per_window: int = 10,
                                maintenance_windows: Optional[List[datetime]] = None) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """
        Generate a remediation plan that respects operational constraints.
        
        Args:
            prioritized_vulns: Output from prioritize_for_environment()
            max_vulns_per_window: Maximum vulnerabilities to patch per maintenance window
            maintenance_windows: List of available maintenance windows
            
        Returns:
            Tuple of (DataFrame with remediation schedule, DataFrame with batch summary)
        """
        if maintenance_windows is None:
            # Generate weekly maintenance windows for next 3 months
            maintenance_windows = [
                datetime.now() + timedelta(weeks=i) 
                for i in range(1, 13)
            ]
        
        # Group vulnerabilities by priority tier
        remediation_plan = []
        
        for window_idx, window in enumerate(maintenance_windows):
            # Get next batch of vulnerabilities
            start_idx = window_idx * max_vulns_per_window
            end_idx = start_idx + max_vulns_per_window
            
            batch = prioritized_vulns.iloc[start_idx:end_idx].copy()
            if len(batch) == 0:
                break
                
            batch['maintenance_window'] = window
            batch['batch_number'] = window_idx + 1
            remediation_plan.append(batch)
        
        plan_df = pd.concat(remediation_plan, ignore_index=True)
        
        # Add summary statistics per batch
        batch_summary = plan_df.groupby('batch_number').agg({
            'contextual_risk_score': ['mean', 'sum'],
            'id': 'count'
        })
        
        return plan_df, batch_summary
    
    def simulate_risk_reduction(self, remediation_plan: pd.DataFrame,
                              current_risk_score: float) -> pd.DataFrame:
        """
        Simulate how risk score changes as vulnerabilities are remediated.
        
        Returns DataFrame showing risk reduction over time.
        """
        risk_timeline = []
        remaining_risk = current_risk_score
        
        for batch_num in remediation_plan['batch_number'].unique():
            batch = remediation_plan[remediation_plan['batch_number'] == batch_num]
            
            # Calculate risk reduction from this batch
            risk_reduced = batch['contextual_risk_score'].sum()
            remaining_risk = max(0, remaining_risk - risk_reduced)
            
            risk_timeline.append({
                'batch_number': batch_num,
                'maintenance_window': batch['maintenance_window'].iloc[0],
                'vulns_patched': len(batch),
                'risk_reduced': risk_reduced,
                'remaining_risk': remaining_risk,
                'risk_reduction_pct': (1 - remaining_risk/current_risk_score) * 100
            })
        
        return pd.DataFrame(risk_timeline)


def demo_contextual_prioritization():
    """Demonstrate the contextual prioritizer with sample data."""
    print("=== TWX Contextual Vulnerability Prioritizer Demo ===\n")
    
    # Initialize the prioritizer
    prioritizer = ContextualPrioritizer()
    
    # Sample asset inventory
    asset_inventory = pd.DataFrame([
        {'asset_id': 'WEB-001', 'vendor': 'Apache', 'product': 'HTTP Server', 'version': '2.4', 'asset_type': 'Web Server'},
        {'asset_id': 'DB-001', 'vendor': 'Oracle', 'product': 'Database', 'version': '19c', 'asset_type': 'Database'},
        {'asset_id': 'APP-001', 'vendor': 'Microsoft', 'product': 'Exchange', 'version': '2019', 'asset_type': 'Email Server'},
        {'asset_id': 'FW-001', 'vendor': 'Cisco', 'product': 'ASA', 'version': '9.16', 'asset_type': 'Firewall'},
    ])
    
    # Business criticality scores (0-1 scale)
    business_criticality = {
        'WEB-001': 0.9,  # Critical web server
        'DB-001': 1.0,   # Mission-critical database
        'APP-001': 0.7,  # Important email server
        'FW-001': 0.8,   # Important firewall
    }
    
    # Network exposure
    network_exposure = {
        'WEB-001': 'internet',
        'DB-001': 'internal',
        'APP-001': 'dmz',
        'FW-001': 'internet',
    }
    
    # Operational constraints
    operational_constraints = {
        'maintenance_windows': 'monthly',
        'requires_testing': True,
        'max_downtime_hours': 4
    }
    
    try:
        # Run prioritization
        print("Analyzing vulnerabilities for your environment...")
        prioritized_vulns = prioritizer.prioritize_for_environment(
            asset_inventory,
            business_criticality,
            network_exposure,
            operational_constraints
        )
        
        if len(prioritized_vulns) > 0:
            print(f"\nFound {len(prioritized_vulns)} vulnerabilities affecting your assets")
            
            # Show top 10 prioritized vulnerabilities
            print("\nTop 10 Prioritized Vulnerabilities:")
            print("-" * 100)
            
            top_vulns = prioritized_vulns.head(10)[
                ['id', 'asset_id', 'base_score', 'contextual_risk_score', 'priority_tier', 'vuln_type']
            ]
            
            for _, vuln in top_vulns.iterrows():
                print(f"CVE: {vuln['id']} | Asset: {vuln['asset_id']} | "
                      f"Base Score: {vuln['base_score']:.1f} | "
                      f"Contextual Score: {vuln['contextual_risk_score']:.1f} | "
                      f"Priority: {vuln['priority_tier']} | Type: {vuln['vuln_type']}")
            
            # Generate remediation plan
            print("\n\nGenerating Remediation Plan...")
            plan, summary = prioritizer.generate_remediation_plan(prioritized_vulns)
            
            print("\nRemediation Plan Summary:")
            print(summary)
            
            # Save results
            output_dir = "analysis/contextual_reports"
            os.makedirs(output_dir, exist_ok=True)
            
            prioritized_vulns.to_csv(f"{output_dir}/prioritized_vulnerabilities.csv", index=False)
            plan.to_csv(f"{output_dir}/remediation_plan.csv", index=False)
            
            print(f"\nResults saved to {output_dir}/")
            
        else:
            print("\nNo vulnerabilities found for the specified assets.")
            print("This could mean:")
            print("1. The asset names don't match any in the database")
            print("2. No vulnerabilities are recorded for these specific products")
            print("3. The database needs to be updated with more recent data")
            
    except Exception as e:
        print(f"Error during prioritization: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    demo_contextual_prioritization()