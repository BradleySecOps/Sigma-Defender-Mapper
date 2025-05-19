import argparse
import os
import sys # Added for sys.argv check
import pandas as pd
import yaml
from collections import Counter
from apply_translated_rule import apply_sigma_rule_to_csv # Keep this import
import multiprocessing
from functools import partial
import unicodedata

try:
    from colorama import init, Fore, Style
    init(autoreset=True) # Initialize colorama
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False
    # Define Fore and Style as empty strings if colorama is not available
    class Fore:
        RED = ''
        GREEN = ''
        YELLOW = ''
        BLUE = ''
        MAGENTA = ''
        CYAN = ''
        WHITE = ''
    class Style:
        BRIGHT = ''
        RESET_ALL = ''

# This function needs to be at the top level for pickling by multiprocessing
def process_rule_worker(rule_path, target_csv_path, field_mapping_path):
    """
    Worker function to process a single Sigma rule.
    Returns a tuple: (rule_path, matching_df, rule_title, rule_id, rule_level, unmapped_fields_set)
    or (rule_path, None, error_title, error_id, "N/A_LEVEL", unmapped_fields_set) if an error occurs.
    """
    unmapped_fields_set = set() # Initialize
    rule_level_for_return = "N/A_LEVEL" # Default in case of early exit
    try:
        # Expect: matching_df, rule_title, rule_id, rule_level, unmapped_fields
        matching_df, rule_title, rule_id, rule_level_from_apply, unmapped_fields_set = apply_sigma_rule_to_csv(
            rule_path,
            target_csv_path,
            field_mapping_path
        )
        rule_level_for_return = rule_level_from_apply # Capture level even if no matches or error later

        if matching_df is not None and not matching_df.empty:
            # 'Sigma Rule Level' is already added by apply_sigma_rule_to_csv
            matching_df['Sigma Rule Title'] = rule_title
            matching_df['Sigma Rule ID'] = rule_id
            matching_df['Sigma Rule Path'] = rule_path
            return rule_path, matching_df, rule_title, rule_id, rule_level_for_return, unmapped_fields_set
        elif matching_df is not None: # Empty DataFrame, no matches
            return rule_path, pd.DataFrame(), rule_title, rule_id, rule_level_for_return, unmapped_fields_set
        else: # An error occurred within apply_sigma_rule_to_csv
            # rule_title contains the error message here
            return rule_path, None, rule_title, "ERROR_ID", rule_level_for_return, unmapped_fields_set

    except Exception as e:
        return rule_path, None, f"Worker error: {os.path.basename(rule_path)}", "WORKER_ERROR_ID", rule_level_for_return, unmapped_fields_set

def is_event_suppressed(event_row, suppression_rules):
    """
    Checks if a single event (DataFrame row) matches any suppression rule.
    An event is suppressed if ALL conditions within a single suppression rule are met.
    """
    if not suppression_rules:
        return False

    for rule in suppression_rules:
        if not isinstance(rule, dict) or 'conditions' not in rule or not isinstance(rule['conditions'], list):
            continue

        all_conditions_met_for_this_rule = True # Assume true until a condition fails
        if not rule['conditions']: # If a rule has no conditions, it doesn't suppress anything by itself
            all_conditions_met_for_this_rule = False
            
        for condition in rule['conditions']:
            if not isinstance(condition, dict) or not all(k in condition for k in ['field', 'operator', 'value']) and not all(k in condition for k in ['field', 'operator', 'values']):
                all_conditions_met_for_this_rule = False
                break # Invalid condition, so this suppression rule cannot be met

            field_name = condition['field']
            operator = condition['operator'].lower() # Case-insensitive operator matching
            
            # Ensure the event_row actually has the field, otherwise it cannot match
            if field_name not in event_row or pd.isna(event_row[field_name]):
                all_conditions_met_for_this_rule = False
                break # Field not in event or is NaN, condition cannot be met

            event_value_normalized = unicodedata.normalize('NFKC', str(event_row[field_name])).strip().lower()

            condition_match = False
            if operator == "equals":
                condition_value_normalized = unicodedata.normalize('NFKC', str(condition['value'])).strip().lower()
                condition_match = event_value_normalized == condition_value_normalized
            elif operator == "contains":
                condition_value_normalized = unicodedata.normalize('NFKC', str(condition['value'])).strip().lower()
                condition_match = condition_value_normalized in event_value_normalized
            elif operator == "startswith":
                condition_value_normalized = unicodedata.normalize('NFKC', str(condition['value'])).strip().lower()
                condition_match = event_value_normalized.startswith(condition_value_normalized)
            elif operator == "endswith": # Ensure this operator is also handled if it exists or is planned
                condition_value_normalized = unicodedata.normalize('NFKC', str(condition['value'])).strip().lower()
                condition_match = event_value_normalized.endswith(condition_value_normalized)
            elif operator == "in":
                normalized_condition_values = [unicodedata.normalize('NFKC', str(v)).strip().lower() for v in condition.get('values', [])]
                condition_match = event_value_normalized in normalized_condition_values
            elif operator == "contains_any":
                normalized_condition_values = [unicodedata.normalize('NFKC', str(v)).strip().lower() for v in condition.get('values', [])]
                condition_match = any(v_norm in event_value_normalized for v_norm in normalized_condition_values)
            elif operator == "startswith_any":
                normalized_condition_values = [unicodedata.normalize('NFKC', str(v)).strip().lower() for v in condition.get('values', [])]
                condition_match = any(event_value_normalized.startswith(v_norm) for v_norm in normalized_condition_values)
            elif operator == "endswith_any":
                normalized_condition_values = [unicodedata.normalize('NFKC', str(v)).strip().lower() for v in condition.get('values', [])]
                condition_match = any(event_value_normalized.endswith(v_norm) for v_norm in normalized_condition_values)
            # Add more operators here if needed (e.g., regex)

            if not condition_match:
                all_conditions_met_for_this_rule = False
                break # One condition failed, so this suppression rule is not met

        if all_conditions_met_for_this_rule:
            return True # Event matched all conditions of this suppression rule

    return False # Event did not match all conditions of any suppression rule
def scan_rules_for_products(sigma_rules_dir):
    """Scans all rules in the directory to find unique products and their counts."""
    product_counts = Counter()
    rule_files = []
    for root, _, files in os.walk(sigma_rules_dir):
        for file in files:
            if file.endswith(".yml"):
                rule_path = os.path.join(root, file)
                rule_files.append(rule_path)
                try:
                    current_rule_content = None
                    try:
                        with open(rule_path, 'r', encoding='utf-8') as f_rule:
                            current_rule_content = yaml.safe_load(f_rule)
                    except Exception: 
                        continue 

                    if current_rule_content and isinstance(current_rule_content, dict):
                        logsource = current_rule_content.get('logsource', {})
                        product = logsource.get('product')
                        if product:
                            product_counts[product] += 1
                        else:
                            product_counts['undefined_product'] +=1 
                except Exception as e:
                    continue
    
    if not product_counts:
        print("No products found in the specified Sigma rules directory.")
        return [], [] 

    print("\nAvailable products in the Sigma rules directory:")
    sorted_products = sorted(product_counts.items(), key=lambda item: item[0]) 
    
    product_map = {}
    for i, (product, count) in enumerate(sorted_products):
        print(f"  {i+1}: {product} ({count} rules)")
        product_map[i+1] = product
        
    while True:
        try:
            choices_str = input("Enter the numbers of the products to scan (comma-separated, or 'all'): ")
            if choices_str.strip().lower() == 'all':
                selected_products = [p[0] for p in sorted_products if p[0] != 'undefined_product'] 
                if not selected_products and 'undefined_product' in product_counts: 
                    selected_products = ['undefined_product']
                elif not selected_products: 
                     print("No products available to select.")
                     return [], rule_files 
                break
            
            selected_indices = [int(x.strip()) for x in choices_str.split(',')]
            selected_products = []
            valid_selection = True
            for index in selected_indices:
                if index in product_map:
                    selected_products.append(product_map[index])
                else:
                    print(f"Invalid selection: {index}. Please choose from the list.")
                    valid_selection = False
                    break
            if valid_selection and selected_products:
                break
            elif not selected_products and valid_selection : 
                 print("No products selected. Please make a valid selection or type 'all'.")
            elif not valid_selection:
                 pass 
            else: 
                 print("Please make a selection.")

        except ValueError:
            print("Invalid input. Please enter numbers separated by commas, or 'all'.")
            
    print(f"Selected products for scanning: {', '.join(selected_products)}")
    return selected_products, rule_files


def run_all_sigma_rules(sigma_rules_dir, target_csv_path, output_csv_path, field_mapping_path='field_mapping.json', num_workers=None, allowlist_path='allowlist.yml'):
    """
    Runs selected Sigma rules in a directory against a target CSV using multiprocessing,
    applies allowlisting, and aggregates results.
    """
    all_matching_dfs = [] # Store DataFrames from workers
    rule_processing_summary = [] # List to store dicts for summary report
    processed_rules_count = 0
    rules_with_matches_count = 0
    total_matching_events = 0

    if not os.path.isdir(sigma_rules_dir):
        print(f"Error: Sigma rules directory '{sigma_rules_dir}' not found.")
        return

    print(f"Scanning for products in: {sigma_rules_dir}")
    selected_products, all_rule_files_paths = scan_rules_for_products(sigma_rules_dir)

    if not all_rule_files_paths:
        print("No rule files found in the specified directory or subdirectories. Exiting.")
        return
        
    rules_to_process_args = [] # List of (rule_path, target_csv_path, field_mapping_path)
    
    # Filter rules based on product selection before creating tasks for the pool
    temp_rules_to_process_paths = []
    if not selected_products: 
        temp_rules_to_process_paths = all_rule_files_paths
    else:
        for rule_path in all_rule_files_paths:
            current_rule_content = None
            try:
                with open(rule_path, 'r', encoding='utf-8') as f_rule:
                    rule_data_for_product_check = yaml.safe_load(f_rule) 
                    if isinstance(rule_data_for_product_check, dict):
                        logsource = rule_data_for_product_check.get('logsource', {})
                        product = logsource.get('product')
                        if product in selected_products or (product is None and 'undefined_product' in selected_products):
                            temp_rules_to_process_paths.append(rule_path)
            except Exception:
                continue
    
    if not temp_rules_to_process_paths:
        print("No rules match the selected product criteria. Exiting.")
        return

    # Prepare arguments for worker function
    for rule_path in temp_rules_to_process_paths:
        rules_to_process_args.append((rule_path, target_csv_path, field_mapping_path))

    total_rules_to_scan = len(rules_to_process_args)
    if total_rules_to_scan == 0:
        print("No rules to process after filtering. Exiting.")
        return

    print(f"\nStarting to process {total_rules_to_scan} rules for selected products: {', '.join(selected_products) if selected_products else 'all available/undefined'}")
    print(f"Target CSV: {target_csv_path}")
    print(f"Output will be saved to: {output_csv_path}")

    # Load allowlist
    loaded_suppression_rules = []
    if allowlist_path and os.path.exists(allowlist_path):
        try:
            with open(allowlist_path, 'r', encoding='utf-8') as f_allow:
                allowlist_data = yaml.safe_load(f_allow)
                if isinstance(allowlist_data, dict) and 'suppressions' in allowlist_data:
                    loaded_suppression_rules = allowlist_data['suppressions']
                    if loaded_suppression_rules:
                         print(f"Successfully loaded {len(loaded_suppression_rules)} suppression rules from {allowlist_path}")
                    else:
                        print(f"Allowlist file {allowlist_path} loaded, but no suppression rules found or 'suppressions' key is empty.")
                else:
                    print(f"Warning: Allowlist file {allowlist_path} is not in the expected format (missing 'suppressions' key or not a dictionary). Proceeding without allowlisting.")
        except Exception as e:
            print(f"Warning: Could not load or parse allowlist file {allowlist_path}: {e}. Proceeding without allowlisting.")
    elif allowlist_path:
        print(f"Warning: Allowlist file '{allowlist_path}' not found. Proceeding without allowlisting.")
    else:
        print("No allowlist file specified. Proceeding without allowlisting.")
    
    # Determine number of workers
    if num_workers is None:
        num_workers = os.cpu_count()
    print(f"Using {num_workers} worker processes.")

    # Using multiprocessing Pool
    # The target_csv_path and field_mapping_path are common to all tasks,
    # so we can use functools.partial to create a new function with these arguments pre-filled.
    # However, apply_sigma_rule_to_csv is already complex.
    # Let's pass them as part of the iterable to the worker.
    
    # The worker function `process_rule_worker` now takes (rule_path, target_csv_path, field_mapping_path)
    # We've prepared `rules_to_process_args` as a list of these tuples.

    with multiprocessing.Pool(processes=num_workers) as pool:
        results = []
        # Use imap_unordered for potentially better memory usage with many tasks
        # and to get results as they complete for progress reporting.
        for i, result_tuple in enumerate(pool.starmap(process_rule_worker, rules_to_process_args)):
            # result_tuple is (rule_path, matching_df, rule_title, rule_id, rule_level, unmapped_fields_set)
            processed_rules_count += 1
            progress_percentage = (processed_rules_count / total_rules_to_scan) * 100
            
            _r_path, df_match, r_title, _r_id, r_level, unmapped_fields = result_tuple
            rule_basename = os.path.basename(_r_path) if _r_path else "N/A"
            
            current_rule_summary = {
                "Rule Path": _r_path,
                "Rule Title": r_title,
                "Rule ID": _r_id,
                "Rule Level": r_level, # Added Rule Level
                "Matches Found": 0,
                "Status": "Processed - No Matches",
                "Error Info": "",
                "Unmapped Fields": ", ".join(sorted(list(unmapped_fields))) if unmapped_fields else ""
            }
 
            if df_match is not None and not df_match.empty:
                original_num_matches = len(df_match)
                
                # Apply allowlisting if rules are loaded
                if loaded_suppression_rules:
                    # Create a boolean Series: True if event should be suppressed
                    suppress_mask = df_match.apply(is_event_suppressed, axis=1, suppression_rules=loaded_suppression_rules)
                    non_suppressed_df = df_match[~suppress_mask]
                    num_suppressed = original_num_matches - len(non_suppressed_df)
                else:
                    non_suppressed_df = df_match
                    num_suppressed = 0

                if not non_suppressed_df.empty:
                    num_actual_matches = len(non_suppressed_df)
                    print(" " * 150, end='\r', flush=True) # Clear progress line
                    success_msg = f"SUCCESS: Matches found for rule: {r_title} ({rule_basename}) - {num_actual_matches} events"
                    if num_suppressed > 0:
                        success_msg += f" ({num_suppressed} suppressed by allowlist)."
                    else:
                        success_msg += "."
                    print(success_msg)
                    
                    all_matching_dfs.append(non_suppressed_df)
                    rules_with_matches_count += 1
                    total_matching_events += num_actual_matches
                    current_rule_summary["Matches Found"] = num_actual_matches
                    current_rule_summary["Status"] = "Processed - Matches Found"
                    if num_suppressed > 0 and num_actual_matches == 0:
                        current_rule_summary["Status"] = "Processed - All Matches Suppressed"
                    elif num_suppressed > 0:
                         current_rule_summary["Status"] += f" ({num_suppressed} Suppressed)"

                elif num_suppressed > 0 and original_num_matches > 0 : # All matches were suppressed
                    print(" " * 150, end='\r', flush=True) # Clear progress line
                    print(f"INFO: All {original_num_matches} matches for rule: {r_title} ({rule_basename}) were suppressed by allowlist.")
                    current_rule_summary["Matches Found"] = 0
                    current_rule_summary["Status"] = "Processed - All Matches Suppressed"
                # If df_match was originally empty, or became empty after suppression and no suppression occurred,
                # it falls through to the "Processed - No Matches" default status for current_rule_summary.

            elif df_match is None: # Error in worker or apply_sigma_rule_to_csv
                # Clear the progress line before printing error
                print(" " * 150, end='\r', flush=True)
                print(f"ERROR: Processing rule: {r_title} ({rule_basename}). Title might be error message.")
                current_rule_summary["Status"] = "Error"
                current_rule_summary["Error Info"] = r_title # r_title contains error message in this case
            # If df_match is an empty DataFrame, status remains "Processed - No Matches"
            
            rule_processing_summary.append(current_rule_summary)
 
            # Update progress on the same line
            # Ensure the progress message is long enough to overwrite previous success/error messages if they were shorter
            progress_message = f"Progress: {progress_percentage:.1f}% ({processed_rules_count}/{total_rules_to_scan}) - Last: {rule_basename}"
            print(f"{progress_message:<150}", end='\r', flush=True) # Pad to ensure line clearing
 
    # Final newline after loop to move past the progress bar
    print("\n" * 2) # Add extra newlines to ensure "Scan Complete" is clearly visible
    print("--- Scan Complete ---")
    if all_matching_dfs:
        final_results_df = pd.concat(all_matching_dfs, ignore_index=True)
        
        # De-duplication (optional, as it adds overhead and might not be desired if rule attribution is key)
        # For now, we'll skip complex de-duplication as matches are already rule-attributed.
        # If you need to de-duplicate events that matched multiple rules:
        # original_cols = [col for col in final_results_df.columns if col not in ['Sigma Rule Title', 'Sigma Rule ID', 'Sigma Rule Path']]
        # if original_cols:
        #     final_results_df.drop_duplicates(subset=original_cols, keep='first', inplace=True)
        # else:
        #     final_results_df.drop_duplicates(keep='first', inplace=True)

        try:
            output_dir = os.path.dirname(output_csv_path)
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir)
            final_results_df.to_csv(output_csv_path, index=False, encoding='utf-8')
            print(f"Aggregated results saved to {output_csv_path}")
        except Exception as e:
            print(f"Error saving results to {output_csv_path}: {e}")
    else:
        print("No matching events found for any of the processed Sigma rules.")

    print(f"Total rules processed: {processed_rules_count}")
    print(f"Rules with matches: {rules_with_matches_count}")
    print(f"Total matching event instances found: {total_matching_events}")

    # Save the summary report
    if rule_processing_summary:
        summary_df = pd.DataFrame(rule_processing_summary)
        summary_output_path = os.path.splitext(output_csv_path)[0] + "_summary_report.csv"
        try:
            summary_df.to_csv(summary_output_path, index=False, encoding='utf-8')
            print(f"Rule processing summary report saved to {summary_output_path}")
        except Exception as e:
            print(f"Error saving summary report to {summary_output_path}: {e}")
    else:
        print("No rules were processed to generate a summary report.")


def display_banner():
    """Displays an attractive banner when the script is run, especially without arguments."""
    banner = f"""
{Style.BRIGHT}{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════════════════╗
{Style.BRIGHT}{Fore.CYAN}║{Fore.WHITE}    🛡️  Sigma Defender CSV Hunter 🏹  (Made by Bradley Carpenter)     {Fore.CYAN}║
{Style.BRIGHT}{Fore.CYAN}╚══════════════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.GREEN}This script scans Microsoft Defender timeline CSVs with thousands of Sigma rules
for deep, offline threat hunting and enhanced incident response.

{Fore.YELLOW}Core Functionality:{Style.RESET_ALL}
  - Translates Sigma rule logic to query CSV data.
  - Uses a field mapping JSON ([{Fore.MAGENTA}scripts/field_mapping.json{Style.RESET_ALL}]) for Sigma-to-CSV field translation.
  - Supports multiprocessing for speed and an allowlist ([{Fore.MAGENTA}scripts/allowlist.yml{Style.RESET_ALL}]) for noise reduction.

{Fore.YELLOW}Basic Usage:{Style.RESET_ALL}
  {Fore.CYAN}python scripts/run_all_rules.py {Fore.GREEN}<sigma_rules_directory> {Fore.CYAN}--target_csv {Fore.GREEN}<path_to_timeline.csv> {Fore.CYAN}--output_csv {Fore.GREEN}<report_name.csv>{Style.RESET_ALL}

{Fore.YELLOW}Example:{Style.RESET_ALL}
  {Fore.CYAN}python scripts/run_all_rules.py ./sigma/rules/windows --target_csv timeline.csv --output_csv detected_events.csv{Style.RESET_ALL}

For all options, run: {Fore.CYAN}python scripts/run_all_rules.py --help{Style.RESET_ALL}
"""
    print(banner)

def main():
    # Get the directory of the current script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    default_mapping_path = os.path.join(script_dir, "field_mapping.json")
    default_allowlist_path = os.path.join(script_dir, "allowlist.yml")

    parser = argparse.ArgumentParser(
        description=f"{Fore.GREEN}Runs Sigma rules against a CSV timeline, applying field mappings and allowlisting.{Style.RESET_ALL}",
        formatter_class=argparse.RawTextHelpFormatter, # Allows for better formatting of help text
        epilog=f"{Fore.YELLOW}Example: {Fore.CYAN}python scripts/run_all_rules.py ./sigma/rules/windows --target_csv timeline.csv --output_csv detected_events.csv{Style.RESET_ALL}"
    )
    parser.add_argument("sigma_dir", help="Directory containing Sigma rule .yml files (e.g., path/to/sigma/rules/windows).")
    parser.add_argument("--target_csv", required=True,
                        help="Path to the target CSV data file (e.g., timeline.csv).")
    parser.add_argument("--output_csv", required=True,
                        help="Path to save the aggregated results CSV (e.g., reports/detected_events.csv).")
    parser.add_argument("--mapping", default=default_mapping_path, dest="mapping_file_path",
                        help=f"Path to the field mapping JSON file.\nDefault: {default_mapping_path} (relative to this script).")
    parser.add_argument("--workers", type=int, default=None,
                        help="Number of worker processes for parallel rule scanning.\nDefault: Number of CPU cores.")
    parser.add_argument("--allowlist", default=default_allowlist_path, dest="allowlist_path",
                        help=f"Path to the YAML allowlist file for suppressing known benign events.\nDefault: {default_allowlist_path} (relative to this script).")
    
    # If no arguments (or only script name) or if --help is requested, show banner then proceed
    if len(sys.argv) <= 1 or any(arg in sys.argv for arg in ['-h', '--help']):
        display_banner()
        # If --help was explicitly called, argparse will handle printing help and exiting.
        # If no args were given, we want to show the banner, then let argparse show its error.
        if len(sys.argv) <=1 and not any(arg in sys.argv for arg in ['-h', '--help']):
            # Force parser to print help if only script name is given, as sigma_dir is required
            # This is a bit of a workaround to show our banner *before* argparse's own error for missing args.
            # A more robust way might involve a custom ArgumentParser class, but this is simpler.
            try:
                args = parser.parse_args()
            except SystemExit: # Catch the exit from parse_args when required arg is missing
                 # The banner is already printed. Argparse error will follow.
                raise # Re-raise to let argparse handle the exit
        else: # --help was called
            args = parser.parse_args() # Let argparse print help and exit
            return # Exit after help
    else:
        args = parser.parse_args()


    if not os.path.exists(args.target_csv):
        print(f"{Fore.RED}Error: Target CSV file not found: {args.target_csv}{Style.RESET_ALL}")
        return
    if not os.path.exists(args.mapping_file_path):
        print(f"{Fore.RED}Error: Mapping file not found: {args.mapping_file_path}{Style.RESET_ALL}")
        return
    # Allowlist path is optional, so we don't make its existence mandatory here.
    # The run_all_sigma_rules function will handle if it's not found.

    run_all_sigma_rules(args.sigma_dir, args.target_csv, args.output_csv, args.mapping_file_path, args.workers, args.allowlist_path)

if __name__ == "__main__":
    main()