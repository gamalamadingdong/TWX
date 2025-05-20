"""
Tool to create a gold standard validation dataset for TWX vulnerability classifier.
This extracts a balanced sample from the full dataset for manual validation.
"""

import os
import sys
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split

# Add the project root directory to Python path
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(root_dir)

def create_validation_sample(input_file="analysis/classification_data.csv", 
                            output_file="analysis/validation_sample.csv",
                            sample_size=300, min_per_class=5):
    """
    Create a balanced sample for validation across vulnerability types.
    
    Args:
        input_file: Path to the full dataset CSV
        output_file: Path to save the validation sample
        sample_size: Total sample size to extract
        min_per_class: Minimum samples per class
    
    Returns:
        DataFrame with the extracted sample
    """
    print(f"Loading data from {input_file}")
    df = pd.read_csv(input_file, low_memory=False)
    
    # Get class distribution
    class_counts = df['vuln_type'].value_counts()
    print(f"Found {len(class_counts)} unique vulnerability types")
    
    # Filter classes with very few samples
    valid_classes = class_counts[class_counts >= min_per_class].index
    print(f"Using {len(valid_classes)} classes with at least {min_per_class} samples")
    
    # Calculate samples per class (weighted by class frequency but ensuring minimum)
    total_valid = sum(class_counts[valid_classes])
    samples_per_class = {}
    
    # First allocation based on frequency
    for cls in valid_classes:
        samples_per_class[cls] = max(
            min_per_class,  # At least min_per_class
            int(sample_size * (class_counts[cls] / total_valid))  # Proportional allocation
        )
    
    # Adjust if we're over budget
    total_allocated = sum(samples_per_class.values())
    if total_allocated > sample_size:
        # Scale down proportionally while preserving minimums
        excess = total_allocated - sample_size
        non_min_classes = [c for c, n in samples_per_class.items() if n > min_per_class]
        non_min_total = sum(samples_per_class[c] for c in non_min_classes)
        
        for cls in non_min_classes:
            reduction = int(excess * (samples_per_class[cls] / non_min_total))
            samples_per_class[cls] = max(min_per_class, samples_per_class[cls] - reduction)
    
    # Extract stratified sample
    sample_df = pd.DataFrame()
    for cls, count in samples_per_class.items():
        class_df = df[df['vuln_type'] == cls]
        if len(class_df) <= count:
            # Take all samples if we don't have enough
            class_sample = class_df
        else:
            # Randomly sample
            class_sample = class_df.sample(n=count, random_state=42)
        
        sample_df = pd.concat([sample_df, class_sample])
    
    # Add columns for manual validation
    sample_df['original_type'] = sample_df['vuln_type']
    sample_df['validated_type'] = ''  # To be filled manually
    sample_df['validation_notes'] = ''  # For reviewer notes
    
    # Save the validation sample
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    sample_df.to_csv(output_file, index=False)
    
    print(f"Created validation sample with {len(sample_df)} records")
    print(f"Sample saved to {output_file}")
    
    return sample_df

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Create validation dataset for TWX')
    parser.add_argument('--input', type=str, default="analysis/classification_data.csv",
                        help='Path to the full dataset CSV')
    parser.add_argument('--output', type=str, default="analysis/validation_sample.csv",
                        help='Path to save the validation sample')
    parser.add_argument('--size', type=int, default=300,
                        help='Total sample size to extract')
    parser.add_argument('--min-per-class', type=int, default=5,
                        help='Minimum samples per class')
    
    args = parser.parse_args()
    
    create_validation_sample(
        input_file=args.input,
        output_file=args.output,
        sample_size=args.size,
        min_per_class=args.min_per_class
    )