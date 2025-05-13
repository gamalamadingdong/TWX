import os
import sys
import time

def run_pipeline():
    """Run the complete TWX vulnerability analysis pipeline."""
    start_time = time.time()
    
    # Step 1: Populate the database
    print("\n===== STEP 1: POPULATE DATABASE =====")
    from storage.populate_database import populate_database
    df = populate_database()
    
    # Step 2: Create vulnerability-ATT&CK mappings
    print("\n===== STEP 2: CREATE VULNERABILITY-ATT&CK MAPPINGS =====")
    from analysis.attack_mapping import create_vuln_attack_mappings
    create_vuln_attack_mappings()
    
    # Step 3: Train the vulnerability classifier
    print("\n===== STEP 3: TRAIN VULNERABILITY CLASSIFIER =====")
    from models.vuln_classifier import main as train_classifier
    train_classifier()
    
    # Step 4: Analyze unbiasing effect
    print("\n===== STEP 4: ANALYZE UNBIASING EFFECT =====")
    from analysis.unbiasing_analysis import analyze_unbiasing_effect
    analyze_unbiasing_effect()
    
    # Step 5: Perform risk scoring
    print("\n===== STEP 5: PERFORM RISK SCORING =====")
    from analysis.risk_scoring import analyze_risk_scores
    analyze_risk_scores()
    
    # Report completion
    elapsed_time = time.time() - start_time
    print(f"\nComplete pipeline execution finished in {elapsed_time:.2f} seconds")
    print("Results are available in the analysis/ directory")

if __name__ == "__main__":
    run_pipeline()