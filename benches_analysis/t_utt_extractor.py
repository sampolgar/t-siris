#!/usr/bin/env python3
import json
import pandas as pd
from pathlib import Path
import re

# Define the base directory for Criterion benchmark results
BASE_DIR = Path("target/criterion/t_utt")

def extract_mean_ms(json_file: Path) -> float:
    """Extract the mean execution time in milliseconds from a Criterion JSON file."""
    try:
        with open(json_file, 'r') as f:
            data = json.load(f)
        mean_ns = data['mean']['point_estimate']  # Mean time in nanoseconds
        return mean_ns / 1_000_000  # Convert to milliseconds
    except (FileNotFoundError, KeyError) as e:
        print(f"Error processing {json_file}: {e}")
        return None

def parse_benchmark_id(benchmark_id: str):
    """Parse the benchmark ID to extract operation, N, t, and n parameters."""
    # Example: "token_request/N4_t3_n4"
    try:
        operation = benchmark_id.split('/')[0]
        params = benchmark_id.split('/')[1]
        
        # Skip report directories
        if params == "report":
            return None, None, None, None
        
        # Extract N (participants), t (threshold), and n (attributes)
        n_match = re.search(r'N(\d+)', params)
        t_match = re.search(r't(\d+)', params)
        n_attr_match = re.search(r'n(\d+)', params)
        
        if not (n_match and t_match and n_attr_match):
            return None, None, None, None
            
        n_participants = int(n_match.group(1))
        threshold = int(t_match.group(1))
        attributes = int(n_attr_match.group(1))
        
        return operation, n_participants, threshold, attributes
    except (AttributeError, IndexError) as e:
        print(f"Skipping benchmark ID {benchmark_id} - doesn't match expected format")
        return None, None, None, None

def extract_benchmark_data(base_dir: Path) -> pd.DataFrame:
    """Extract t_utt benchmark data from Criterion directories and return a DataFrame."""
    all_data = []
    
    # Check if base directory exists
    if not base_dir.exists():
        print(f"Error: Base directory {base_dir} does not exist!")
        return pd.DataFrame()
    
    # For each benchmark operation directory
    for bench_dir in base_dir.iterdir():
        if not bench_dir.is_dir():
            continue
        
        operation_name = bench_dir.name
        
        # For each parameter set (subdirectory)
        for param_dir in bench_dir.iterdir():
            if not param_dir.is_dir() or param_dir.name == "report":
                continue
            
            benchmark_id = f"{operation_name}/{param_dir.name}"
            operation, n_participants, threshold, attributes = parse_benchmark_id(benchmark_id)
            
            if None in (operation, n_participants, threshold, attributes):
                continue
                
            # Find the estimates.json file
            report_dir = param_dir / "new"
            if report_dir.exists():
                json_file = report_dir / "estimates.json"
                if json_file.exists():
                    mean_ms = extract_mean_ms(json_file)
                    if mean_ms is not None:
                        all_data.append({
                            "scheme": "t_utt",
                            "operation": operation,
                            "n_participants": n_participants,
                            "threshold": threshold,
                            "attributes": attributes,
                            "mean_ms": mean_ms
                        })
    
    if not all_data:
        print("No benchmark data found in the specified directory!")
        return pd.DataFrame()
    
    df = pd.DataFrame(all_data)
    
    # Define custom operation order
    operation_order = [
        "token_request",
        "t_issue",
        "t_issue_no_verify",
        "aggregate_with_verify",
        "aggregate_no_verify",
        "prove",
        "verify"
    ]
    
    # Create a category dtype with our custom order
    df["operation"] = pd.Categorical(
        df["operation"],
        categories=operation_order,
        ordered=True
    )
    
    # Sort by operation (in our custom order), then by other columns
    return df.sort_values([
        "operation", 
        "n_participants", 
        "threshold", 
        "attributes"
    ])

def main():
    """Main function to extract benchmark data and save results."""
    print(f"Extracting benchmark data from {BASE_DIR}")
    benchmark_df = extract_benchmark_data(BASE_DIR)
    
    if benchmark_df.empty:
        print("No data found. Please ensure benchmarks have been run.")
        return
    
    # Save to CSV in current directory
    csv_file = "t_utt_benchmarks.csv"
    benchmark_df.to_csv(csv_file, index=False)
    print(f"Benchmark data successfully saved to {csv_file}")
    
    # Print basic information
    print(f"\nExtracted {benchmark_df.shape[0]} benchmark data points")
    print(f"Operations: {sorted(benchmark_df['operation'].unique())}")
    print(f"N (participants): {sorted(benchmark_df['n_participants'].unique())}")
    print(f"t (thresholds): {sorted(benchmark_df['threshold'].unique())}")
    print(f"n (attributes): {sorted(benchmark_df['attributes'].unique())}")
    
    print("Data saved in the requested format with columns: scheme, operation, n_participants, threshold, attributes, mean_ms")

if __name__ == "__main__":
    main()