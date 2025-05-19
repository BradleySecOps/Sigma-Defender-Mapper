import argparse
import pandas as pd
import yaml # For parsing Sigma rule YAML (optional, can just read as text)
import os

# Define the columns to extract from the CSV for quick review
# These are common fields used in Sigma rules and present in your CSV
RELEVANT_CSV_COLUMNS = [
    'Event Time', 'Action Type', 'File Name', 'Folder Path',
    'Process Command Line', 'Initiating Process File Name',
    'Initiating Process Folder Path', 'Initiating Process Command Line',
    'Sigma Rule Title', 'Sigma Rule ID', 'Sigma Rule Path'
]

def get_sigma_rule_content(rule_path):
    """Reads and returns the content of a Sigma rule file."""
    if not rule_path or pd.isna(rule_path):
        return "Sigma rule path is missing or invalid."
    try:
        # Ensure the path uses correct OS separators if needed, though os.path.join usually handles this.
        # Assuming the script runs from the project root where 'sigma' directory exists.
        # If rule_path is already relative to project root, this is fine.
        # If rule_path might be absolute, os.path.join might not be what we want.
        # For now, assume rule_path is as it appears in the CSV.
        if not os.path.exists(rule_path):
            return f"Sigma rule file not found at: {rule_path}"
        with open(rule_path, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception as e:
        return f"Error reading Sigma rule file {rule_path}: {e}"

def analyze_timeline_export(csv_filepath): # Removed default value
    """
    Reads the timeline export CSV, and for each event, prints relevant event data
    and the content of the associated Sigma rule.
    """
    if not csv_filepath:
        print("Error: No CSV filepath provided.")
        return
    try:
        df = pd.read_csv(csv_filepath)
    except FileNotFoundError:
        print(f"Error: The file {csv_filepath} was not found.")
        return
    except Exception as e:
        print(f"Error reading CSV file {csv_filepath}: {e}")
        return

    for index, row in df.iterrows():
        print(f"\n\n{'='*40} Event {index + 1} {'='*40}")

        print("\n--- CSV Event Data ---")
        for col in RELEVANT_CSV_COLUMNS:
            if col in row.index: # Check if column name is in the Series' index
                print(f"{col}: {row[col]}")
            else:
                print(f"{col}: Not found in CSV row (Column name missing from Series index)")

        sigma_rule_path = row.get('Sigma Rule Path')
        print("\n--- Sigma Rule Content ---")
        if sigma_rule_path and pd.notna(sigma_rule_path):
            # Attempt to make path relative to script if it's not already,
            # assuming 'sigma' is a subdirectory in the workspace.
            # This might need adjustment based on how paths are stored in the CSV.
            # If paths in CSV are like "sigma\\rules\\...", they are already relative.
            # If they are absolute, this logic might be incorrect.
            # For now, using the path as is from the CSV.
            rule_content = get_sigma_rule_content(sigma_rule_path)
            print(f"Path: {sigma_rule_path}\n")
            print(rule_content)
        else:
            print("Sigma Rule Path not found or is invalid in this row.")

        print(f"\n{'='*40} End of Event {index + 1} {'='*40}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze a timeline export CSV against Sigma rules.")
    parser.add_argument("csv_filepath", help="Path to the timeline export CSV file.")
    args = parser.parse_args()
    
    analyze_timeline_export(args.csv_filepath)
    print("\n\nAnalysis helper script finished.")