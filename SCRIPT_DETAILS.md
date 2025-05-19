# Python Script Details

This document provides a detailed explanation of each Python script used in the Sigma Rule to Defender CSV Mapping Project. All scripts are located in the `scripts/` directory.

## Core Scripts

### 1. `scripts/define_field_mapping.py`
*   **Purpose:** This script is used to manually define the mappings between Sigma rule fields and the corresponding columns in the Defender CSV data (`timeline.csv`). It also defines a crucial mapping from Sigma `logsource.category` to CSV `Action Type` values (stored under `_logsource_category_to_action_type_`).
*   **Input:** None directly. The mappings are defined within the script's code.
*   **Output:** [`scripts/field_mapping.json`](scripts/field_mapping.json:1). This JSON file acts as the central "dictionary" for the translation process, consulted by other scripts.
*   **Interaction:** Its output, [`scripts/field_mapping.json`](scripts/field_mapping.json:1), is critical for [`scripts/apply_translated_rule.py`](scripts/apply_translated_rule.py:1) and consequently [`scripts/run_all_rules.py`](scripts/run_all_rules.py:1).
*   **Usage:** Run `python scripts/define_field_mapping.py` to regenerate [`scripts/field_mapping.json`](scripts/field_mapping.json:1) after modifying mappings.

### 2. `scripts/apply_translated_rule.py`
*   **Purpose:** This is the core engine for processing a single Sigma rule against CSV data.
*   **Functionality:**
    *   Loads [`scripts/field_mapping.json`](scripts/field_mapping.json:1).
    *   Parses an input Sigma rule (`.yml`).
    *   Performs **Action Type Pre-filtering**: Utilizes the `_logsource_category_to_action_type_` mapping from [`scripts/field_mapping.json`](scripts/field_mapping.json:1) to first filter the input CSV DataFrame by relevant `Action Type` values. This significantly speeds up processing.
    *   Translates the Sigma rule's `detection` section fields and conditions into pandas DataFrame queries based on the CSV column mappings.
    *   Supports various Sigma operators (e.g., `endswith`, `startswith`, `contains`, `equals`, `regex`, `CIDR`).
    *   Evaluates complex Sigma `detection.condition` strings (e.g., `selection1 and not (selection2 or 1 of filter_*)`) using a Shunting-yard algorithm and an RPN evaluator.
    *   Intelligently constructs full file paths for evaluation when Sigma conditions imply a path, using a `PATH_COMPONENT_MAP`.
*   **Input:**
    *   Path to a Sigma rule (`.yml` file).
    *   `--csv`: Path to the CSV data file (e.g., `timeline.csv` in the root directory).
    *   Relies on [`scripts/field_mapping.json`](scripts/field_mapping.json:1) being present (default path is relative to the script).
*   **Output:** A pandas DataFrame containing rows from the CSV that match the rule's logic. Prints matches to standard output.
*   **Interaction:** Reads [`scripts/field_mapping.json`](scripts/field_mapping.json:1). It is called by [`scripts/run_all_rules.py`](scripts/run_all_rules.py:1) for each rule.
*   **Usage (Standalone):** `python scripts/apply_translated_rule.py path/to/sigma_rule.yml --csv your_data.csv`

### 3. `scripts/run_all_rules.py`
*   **Purpose:** Orchestrates the scanning of multiple Sigma rules from a specified directory against a target CSV file. This is the primary script for threat hunting.
*   **Functionality:**
    *   **Interactive Product Selection**: Prompts the user to select which `logsource.product` (e.g., `windows`, `linux`) rules they want to run.
    *   **Multiprocessing**: Leverages the `multiprocessing` module to process rules in parallel.
    *   **Allowlisting/Suppression**: Supports an allowlist (e.g., [`scripts/allowlist.yml`](scripts/allowlist.yml:1)) to suppress known benign events.
    *   **Progress Reporting**: Provides real-time progress updates.
    *   Aggregates all matching, non-suppressed events from all processed rules into a single output CSV file.
    *   **Summary Report**: Generates a companion summary report detailing each rule processed, matches, suppressions, and errors.
*   **Input:**
    *   `<path_to_sigma_rules_directory>`: Directory containing Sigma rule `.yml` files.
    *   `--target_csv`: Path to the timeline data CSV.
    *   `--output_csv`: Path for the consolidated report of detected events.
    *   `--workers` (Optional): Number of worker processes.
    *   `--allowlist` (Optional): Path to the allowlist YAML file (defaults to [`scripts/allowlist.yml`](scripts/allowlist.yml:1)).
    *   Relies on [`scripts/field_mapping.json`](scripts/field_mapping.json:1).
*   **Output:**
    *   A main CSV report file with detected events (e.g., `detected_events_report.csv` in the root directory).
    *   A summary report CSV (e.g., `detected_events_report_summary_report.csv` in the root directory).
*   **Interaction:** Calls [`scripts/apply_translated_rule.py`](scripts/apply_translated_rule.py:1) for each rule. Reads [`scripts/field_mapping.json`](scripts/field_mapping.json:1) and [`scripts/allowlist.yml`](scripts/allowlist.yml:1).
*   **Usage:** `python scripts/run_all_rules.py <rules_dir> --target_csv <timeline.csv> --output_csv <report.csv>`

## Supporting & Utility Scripts

### 4. `scripts/extract_sigma_fields.py`
*   **Purpose:** Analyzes a directory of Sigma rules to extract all unique field names, logsource categories, products, services, and detection value types.
*   **Functionality:** Helps in understanding the scope of fields used across a rule set, which is useful for the initial creation and maintenance of [`scripts/field_mapping.json`](scripts/field_mapping.json:1).
*   **Input:** Path to a directory containing Sigma rules.
*   **Output:** `extracted_sigma_data.json` (in the root directory) - a JSON file containing the extracted unique values.
*   **Interaction:** Reads Sigma rule `.yml` files.
*   **Usage:** `python scripts/extract_sigma_fields.py path/to/sigma/rules/`

### 5. `scripts/analyze_sigma_rules.py`
*   **Purpose:** Provides a deeper analysis of Sigma rule structures, condition patterns, and field usage within a given set of rules.
*   **Functionality:** Can help identify common patterns, complexity of rules, and specific fields that might require careful mapping.
*   **Input:** Path to a directory containing Sigma rules.
*   **Output:** `sigma_analysis_results.json` (in the root directory) - a JSON file detailing the analysis.
*   **Interaction:** Reads Sigma rule `.yml` files.
*   **Usage:** `python scripts/analyze_sigma_rules.py path/to/sigma/rules/`

### 6. `scripts/translate_sigma_rule.py`
*   **Purpose:** A utility to display a human-readable translation of a single Sigma rule's detection logic into CSV-based conditions.
*   **Functionality:** Primarily used for debugging and understanding how a specific rule's logic is interpreted by the system before it's applied to data.
*   **Input:** Path to a single Sigma rule (`.yml` file).
*   **Output:** Prints the translated conditions to the console.
*   **Interaction:** Reads a Sigma rule `.yml` file and [`scripts/field_mapping.json`](scripts/field_mapping.json:1) (default path is relative to the script).
*   **Usage:** `python scripts/translate_sigma_rule.py path/to/your/sigma_rule.yml`

### 7. `scripts/test_translator.py`
*   **Purpose:** A script for testing the [`scripts/translate_sigma_rule.py`](scripts/translate_sigma_rule.py:1) output against a diverse set of Sigma rules.
*   **Functionality:** Helps ensure the translation logic is robust and handles various rule structures correctly.
*   **Input:** Typically configured to point to a directory of test Sigma rules.
*   **Output:** `translator_test_results.json` (in the root directory) or console output indicating success/failure of translations.
*   **Interaction:** Uses [`scripts/translate_sigma_rule.py`](scripts/translate_sigma_rule.py:1) internally. Reads Sigma rules and [`scripts/field_mapping.json`](scripts/field_mapping.json:1).

### 8. `scripts/analyze_timeline_helper.py`
*   **Purpose:** A utility script to read a specified timeline export CSV (generated by [`scripts/run_all_rules.py`](scripts/run_all_rules.py:1)), parse its events, and print detailed event data alongside the content of the Sigma rule that flagged it.
*   **Functionality:** Aids in manual analysis and verification of rule matches, helping to understand why an event was flagged.
*   **Input:** Path to a report CSV file generated by [`scripts/run_all_rules.py`](scripts/run_all_rules.py:1).
*   **Output:** Prints detailed event and rule information to the console.
*   **Interaction:** Reads report CSVs and corresponding Sigma rule files.
*   **Usage:** `python scripts/analyze_timeline_helper.py path/to/report.csv`

### 9. `scripts/analyze_v9_report.py`
*   **Purpose:** This script is designed to analyze a generated report CSV (e.g., `detected_events_report.csv`).
*   **Functionality:** It focuses on specific Sigma Rule IDs (optionally provided as arguments, or defaults to a predefined list), lists unsuppressed events, and details why allowlist conditions were met or failed for those events. This is crucial for refining [`scripts/allowlist.yml`](scripts/allowlist.yml:1).
*   **Input:** Path to a report CSV file generated by [`scripts/run_all_rules.py`](scripts/run_all_rules.py:1). May also take specific rule IDs as arguments.
*   **Output:** Console output detailing event suppression status and allowlist logic.
*   **Interaction:** Reads report CSVs, [`scripts/allowlist.yml`](scripts/allowlist.yml:1) (default path is relative to the script), and potentially Sigma rule files.
*   **Usage:** `python scripts/analyze_v9_report.py <path_to_report.csv> [--rule_ids <ID1> <ID2> ...]`

### 10. `scripts/update_field_mapping.py`
*   **Purpose:** This script helps update or manage the [`scripts/field_mapping.json`](scripts/field_mapping.json:1) file, potentially by incorporating new fields found by [`scripts/extract_sigma_fields.py`](scripts/extract_sigma_fields.py:1) or by providing an interface to modify existing mappings.
*   **Functionality (Assumed):**
    *   Read existing [`scripts/field_mapping.json`](scripts/field_mapping.json:1).
    *   Potentially read `extracted_sigma_data.json` (from root) to identify new, unmapped fields.
    *   Provide a way to add or edit mappings.
    *   Write updates back to [`scripts/field_mapping.json`](scripts/field_mapping.json:1).
*   **Input (Assumed):** [`scripts/field_mapping.json`](scripts/field_mapping.json:1), possibly `extracted_sigma_data.json`.
*   **Output (Assumed):** Updated [`scripts/field_mapping.json`](scripts/field_mapping.json:1).
*   **Interaction (Assumed):** Works closely with [`scripts/field_mapping.json`](scripts/field_mapping.json:1) and potentially the output of [`scripts/extract_sigma_fields.py`](scripts/extract_sigma_fields.py:1).

### 11. `scripts/analyze_allowlist_candidates.py`
*   **Purpose:** This script analyzes detected events (possibly from a report generated by `run_all_rules.py` *before* allowlisting is heavily applied) to help identify patterns or specific event details that could be good candidates for new entries in the [`scripts/allowlist.yml`](scripts/allowlist.yml:1) file.
*   **Functionality (Assumed):**
    *   Read a CSV report of detected events.
    *   Perform analysis or aggregation on event fields (e.g., count occurrences of specific process names, command lines, parent processes).
    *   Suggest potential allowlist rules based on frequency or other heuristics.
*   **Input (Assumed):** A CSV report file (e.g., from [`scripts/run_all_rules.py`](scripts/run_all_rules.py:1)).
*   **Output (Assumed):** Suggestions for allowlist entries, printed to console or a file.
*   **Interaction (Assumed):** Helps in the manual process of creating or refining [`scripts/allowlist.yml`](scripts/allowlist.yml:1).