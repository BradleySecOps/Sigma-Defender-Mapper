import argparse
import pandas as pd
from collections import Counter

def analyze_report_for_allowlisting(report_csv_path, parent_process_name, child_process_name="powershell.exe", top_n=5):
    """
    Analyzes a Sigma alert report CSV to find common command lines and rule titles
    for specific parent-child process relationships, aiding in allowlist creation.

    Args:
        report_csv_path (str): Path to the report CSV file.
        parent_process_name (str): The 'Initiating Process File Name' to filter by.
        child_process_name (str): The 'File Name' (of the process itself) to filter by.
        top_n (int): The number of top common items to display.
    """
    try:
        df = pd.read_csv(report_csv_path, low_memory=False)
    except FileNotFoundError:
        print(f"Error: Report CSV file not found at '{report_csv_path}'")
        return
    except Exception as e:
        print(f"Error reading CSV file '{report_csv_path}': {e}")
        return

    # Define expected column names (these should match your report CSV output)
    # Adjust these if your column names are different.
    parent_process_col = 'Initiating Process File Name'
    child_process_col = 'File Name'
    command_line_col = 'Process Command Line'
    sigma_title_col = 'Sigma Rule Title'

    required_cols = [parent_process_col, child_process_col, command_line_col, sigma_title_col]
    missing_cols = [col for col in required_cols if col not in df.columns]
    if missing_cols:
        print(f"Error: The report CSV is missing required columns: {', '.join(missing_cols)}")
        print(f"Please ensure the report contains: {', '.join(required_cols)}")
        return

    print(f"Analyzing report: '{report_csv_path}'")
    print(f"Filtering for Parent: '{parent_process_name}', Child: '{child_process_name}'\n")

    # Filter the DataFrame
    # Ensure case-insensitive comparison for process names if necessary, though exact match is often better for system processes.
    # For simplicity, using exact match here.
    filtered_df = df[
        (df[parent_process_col].astype(str).str.strip().str.lower() == parent_process_name.strip().lower()) &
        (df[child_process_col].astype(str).str.strip().str.lower() == child_process_name.strip().lower())
    ]

    if filtered_df.empty:
        print(f"No events found matching Parent='{parent_process_name}' and Child='{child_process_name}'.")
        return

    print(f"Found {len(filtered_df)} events matching the criteria.\n")

    # Get top N command lines
    if command_line_col in filtered_df.columns:
        command_line_counts = Counter(filtered_df[command_line_col].dropna())
        print(f"--- Top {top_n} Most Common '{command_line_col}' values: ---")
        if not command_line_counts:
            print("No command line data found for these events.")
        else:
            for cmd, count in command_line_counts.most_common(top_n):
                print(f"  Count: {count}\n  Command: {cmd}\n")
    else:
        print(f"Warning: Column '{command_line_col}' not found in the report.")

    # Get top N Sigma Rule Titles
    if sigma_title_col in filtered_df.columns:
        sigma_title_counts = Counter(filtered_df[sigma_title_col].dropna())
        print(f"\n--- Top {top_n} Most Common '{sigma_title_col}' values: ---")
        if not sigma_title_counts:
            print("No Sigma Rule Title data found for these events.")
        else:
            for title, count in sigma_title_counts.most_common(top_n):
                print(f"  Count: {count}, Title: {title}")
    else:
        print(f"Warning: Column '{sigma_title_col}' not found in the report.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Analyze a Sigma alert report CSV for common patterns to aid in allowlist creation.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "report_csv_path",
        help="Path to the Sigma alert report CSV file (e.g., detected_events_report.csv)."
    )
    
    parser.add_argument(
        "--parent_process",
        required=True,
        help="Name of the parent process (Initiating Process File Name) to filter by (e.g., YourMonitoringTool.exe)."
    )
    parser.add_argument(
        "--child_process",
        default="powershell.exe",
        help="Name of the child process (File Name) to filter by (default: powershell.exe)."
    )
    parser.add_argument(
        "--top_n",
        type=int,
        default=5,
        help="Number of top common items (command lines, rule titles) to display (default: 5)."
    )

    args = parser.parse_args()

    analyze_report_for_allowlisting(
        args.report_csv_path,
        args.parent_process,
        args.child_process,
        args.top_n
    )