import pandas as pd
import os
import unicodedata
import yaml
import argparse # Added argparse

def normalize_str(value):
    """Helper to normalize strings for comparison."""
    return unicodedata.normalize('NFKC', str(value)).strip().lower()

def analyze_report_details(report_path, allowlist_path=None, rule_ids_to_check=None): # Renamed and added rule_ids_to_check
    """
    Analyzes the generated report CSV to check suppression status for specific rules.
    """
    if allowlist_path is None:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        allowlist_path = os.path.join(script_dir, "allowlist.yml")

    if not os.path.exists(report_path):
        print(f"Error: Report file not found at {report_path}")
        return
    if not os.path.exists(allowlist_path):
        print(f"Warning: Allowlist file not found at {allowlist_path}. Cannot show detailed allowlist conditions.")
        loaded_suppression_rules = []
    else:
        try:
            with open(allowlist_path, 'r', encoding='utf-8') as f_allow:
                allowlist_data = yaml.safe_load(f_allow)
                loaded_suppression_rules = allowlist_data.get('suppressions', [])
        except Exception as e:
            print(f"Error loading allowlist {allowlist_path}: {e}")
            loaded_suppression_rules = []

    try:
        df = pd.read_csv(report_path)
    except Exception as e:
        print(f"Error reading CSV file {report_path}: {e}")
        return

    print(f"\n--- Analysis of {os.path.basename(report_path)} ---")

    if not rule_ids_to_check:
        print("Error: No Sigma Rule IDs provided for analysis. Please use the --rule_ids argument.")
        return

    # If rule IDs are provided, create a simple map for iteration
    # We might not have titles here unless we query the Sigma rules themselves,
    # or expect the report CSV to have a reliable 'Sigma Rule Title' for each ID.
    # For now, just use the ID as a placeholder title if needed.
    rules_to_check_map = [{"id": rid, "title": f"Rule ID {rid}"} for rid in rule_ids_to_check]

    for rule_info in rules_to_check_map:
        rule_id = rule_info["id"]
        rule_title_short = rule_info["title"] # This might just be "Rule ID xxxx" if titles aren't easily available
        
        if 'Sigma Rule ID' not in df.columns:
            print(f"Error: 'Sigma Rule ID' column not found in {report_path}. Cannot filter by rule ID.")
            continue

        events = df[df['Sigma Rule ID'] == rule_id]
        
        print(f"\nRule ID {rule_id} (Title Hint: {rule_title_short}):")
        if events.empty:
            print(f"  SUCCESS: No unsuppressed events found for this rule.")
        else:
            print(f"  WARNING: Found {len(events)} unsuppressed event(s) for this rule.")
            print("  Details of unsuppressed events:")
            for index, row in events.iterrows():
                print(f"    - Event Time: {row.get('Event Time', 'N/A')}")
                print(f"      File Name: '{row.get('File Name', 'N/A')}' (Normalized: '{normalize_str(row.get('File Name', 'N/A'))}')")
                print(f"      Initiating Process: '{row.get('Initiating Process File Name', 'N/A')}' (Normalized: '{normalize_str(row.get('Initiating Process File Name', 'N/A'))}')")
                print(f"      Full Sigma Rule Title (from report): {row.get('Sigma Rule Title', 'N/A')}") # Display title from report
                
                relevant_suppression_entries = [
                    s for s in loaded_suppression_rules
                    if any(c.get('field') == 'Sigma Rule ID' and normalize_str(c.get('value')) == normalize_str(rule_id) for c in s.get('conditions', []))
                ]
                if not relevant_suppression_entries:
                    print("      No specific allowlist entry found for this Sigma Rule ID.")
                
                for entry_idx, entry in enumerate(relevant_suppression_entries):
                    print(f"      Checking against allowlist entry: '{entry.get('name', f'Unnamed Entry {entry_idx}')}'")
                    all_cond_met_for_entry = True
                    for cond_idx, cond in enumerate(entry.get('conditions', [])):
                        field = cond.get('field')
                        op = cond.get('operator')
                        val = cond.get('value')
                        vals = cond.get('values')

                        if field == 'Sigma Rule ID':
                            print(f"        Cond {cond_idx+1} ({field} {op} {val or vals}): MET (entry selection criteria)")
                            continue

                        event_val_raw = row.get(field)
                        if pd.isna(event_val_raw):
                            print(f"        Cond {cond_idx+1} ({field} {op} {val or vals}): FAILED (event field '{field}' is NaN or missing in event row)")
                            all_cond_met_for_entry = False
                            break
                        
                        event_val_norm = normalize_str(event_val_raw)
                        cond_match_for_this_cond = False

                        if op == "equals":
                            cond_val_norm = normalize_str(val)
                            cond_match_for_this_cond = event_val_norm == cond_val_norm
                        elif op == "in":
                            norm_list = [normalize_str(v) for v in vals]
                            cond_match_for_this_cond = event_val_norm in norm_list
                        elif op == "endswith_any":
                            norm_list = [normalize_str(v) for v in vals]
                            cond_match_for_this_cond = any(event_val_norm.endswith(v_n) for v_n in norm_list)
                        elif op == "startswith_any": # Added for completeness
                            norm_list = [normalize_str(v) for v in vals]
                            cond_match_for_this_cond = any(event_val_norm.startswith(v_n) for v_n in norm_list)
                        elif op == "contains": # Added for completeness
                            cond_val_norm = normalize_str(val)
                            cond_match_for_this_cond = cond_val_norm in event_val_norm
                        elif op == "contains_any": # Added for completeness
                            norm_list = [normalize_str(v) for v in vals]
                            cond_match_for_this_cond = any(v_n in event_val_norm for v_n in norm_list)
                        
                        status = "MET" if cond_match_for_this_cond else "FAILED"
                        print(f"        Cond {cond_idx+1} ({field} {op} {val or vals}): {status}")
                        print(f"          Event Value (norm): '{event_val_norm}'")
                        if val: print(f"          Cond Value (norm): '{normalize_str(val)}'")
                        if vals: print(f"          Cond Values (norm): {[normalize_str(v) for v in vals]}")

                        if not cond_match_for_this_cond:
                            all_cond_met_for_entry = False
                            break
                    if all_cond_met_for_entry:
                         print(f"      This event SHOULD have been suppressed by allowlist entry: '{entry.get('name', f'Unnamed Entry {entry_idx}')}'")

    print("\n--- End of Analysis ---")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze a generated report CSV for allowlist effectiveness on specific Sigma rules.")
    parser.add_argument("report_csv_path", help="Path to the report CSV file (e.g., detected_events_report.csv).")
    parser.add_argument("--allowlist", default=None, dest="allowlist_path",
                        help="Path to the allowlist YAML file (default: scripts/allowlist.yml relative to this script).")
    parser.add_argument("--rule_ids", nargs='+', required=True,
                        help="List of specific Sigma Rule IDs to check.")
    
    args = parser.parse_args()
    
    analyze_report_details(args.report_csv_path, args.allowlist_path, args.rule_ids)