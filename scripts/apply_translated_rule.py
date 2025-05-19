import argparse
import json
import os
import pandas as pd
import yaml
import re
import ipaddress # Added for CIDR support
from collections.abc import Mapping, Sequence
from functools import reduce # For ORing/ANDing multiple series
import numpy as np
import warnings # Import warnings module

# --- Global Path Component Map ---
PATH_COMPONENT_MAP = {
    'process_creation': {
        'Image': {'file': 'File Name', 'folder': 'Folder Path'},
        'ParentImage': {'file': 'Initiating Process File Name', 'folder': 'Initiating Process Folder Path'},
        'OriginalFileName': {'file': 'File Name', 'folder': 'Folder Path'} # Assuming OriginalFileName might need path context
    },
    'image_load': {
        'ImageLoaded': {'file': 'File Name', 'folder': 'Folder Path'},
        'Image': {'file': 'Initiating Process File Name', 'folder': 'Initiating Process Folder Path'}
    },
    'file_event': {
        'TargetFilename': {'file': 'File Name', 'folder': 'Folder Path'}, # Note: Sigma 'TargetFilename' often IS the full path. This map assumes it might be split.
        'Image': {'file': 'Initiating Process File Name', 'folder': 'Initiating Process Folder Path'}
    }
    # Add other categories and fields as needed
}

# --- Functions adapted/imported from translate_sigma_rule.py ---
def load_field_mapping(mapping_file_path='field_mapping.json'):
    if not os.path.exists(mapping_file_path):
        print(f"Error: Mapping file '{mapping_file_path}' not found.")
        return None
    with open(mapping_file_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def parse_sigma_rule(rule_file_path):
    if not os.path.exists(rule_file_path):
        print(f"Error: Sigma rule file '{rule_file_path}' not found.")
        return None
    try:
        with open(rule_file_path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)
    except yaml.YAMLError as e:
        print(f"Error parsing Sigma rule {rule_file_path}: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred while reading {rule_file_path}: {e}")
        return None

def translate_detection_item(item_key, item_value, category_mapping, unmapped_fields_set):
    translated_conditions = []
    parts = item_key.split('|')
    sigma_field_base = parts[0]
    modifiers_from_key = parts[1:]
    condition_prefix = ""

    if sigma_field_base in category_mapping:
        csv_column = category_mapping[sigma_field_base]
        if csv_column is None:
            condition_prefix = f"SIGMA_FIELD('{sigma_field_base}') NO_CSV_MAPPING_FOR('{sigma_field_base}')"
        else:
            condition_prefix = f"SIGMA_FIELD('{sigma_field_base}') CSV_COLUMN('{csv_column}')"
    else:
        unmapped_fields_set.add(sigma_field_base)
        condition_prefix = f"SIGMA_FIELD('{sigma_field_base}') UNMAPPED_FIELD('{sigma_field_base}')"

    operational_modifiers_map = {
        "contains": "CONTAINS", "endswith": "ENDSWITH", "startswith": "STARTSWITH",
        "re": "REGEX", "cidr": "CIDR"
    }

    primary_operator_str = "EQUALS" 
    for mod_candidate in modifiers_from_key:
        if mod_candidate in operational_modifiers_map:
            primary_operator_str = operational_modifiers_map[mod_candidate]
            break

    has_all_flag = 'all' in modifiers_from_key

    if has_all_flag and primary_operator_str == "EQUALS":
        is_other_op_modifier_present = any(op_mod in modifiers_from_key for op_mod in operational_modifiers_map)
        if not is_other_op_modifier_present:
            primary_operator_str = "CONTAINS"

    if isinstance(item_value, list):
        if has_all_flag: 
            for v in item_value:
                translated_conditions.append(f"{condition_prefix} {primary_operator_str} {json.dumps(v)}")
        else: 
            conditions = [f"{condition_prefix} {primary_operator_str} {json.dumps(v)}" for v in item_value]
            translated_conditions.append(f"({' OR '.join(conditions)})")
    elif isinstance(item_value, str) and item_value == '':
        translated_conditions.append(f"{condition_prefix} IS_EMPTY_STRING")
    elif item_value is None:
        translated_conditions.append(f"{condition_prefix} IS_NULL")
    else: 
        translated_conditions.append(f"{condition_prefix} {primary_operator_str} {json.dumps(item_value)}")
    return translated_conditions

def translate_detection_section(detection_dict, category_mapping, unmapped_fields_set):
    translated_detection = {}
    if not isinstance(detection_dict, Mapping):
        return translated_detection

    for selection_name, selection_conditions in detection_dict.items():
        if selection_name == 'condition':
            continue

        if isinstance(selection_conditions, list): 
            list_of_map_translations = []
            for condition_map_item in selection_conditions:
                map_internal_conditions = []
                if isinstance(condition_map_item, Mapping):
                    for key, value in condition_map_item.items():
                        map_internal_conditions.extend(
                            translate_detection_item(key, value, category_mapping, unmapped_fields_set)
                        )
                if map_internal_conditions:
                    list_of_map_translations.append(map_internal_conditions)
            
            if list_of_map_translations:
                 translated_detection[selection_name] = {"type": "list_of_maps", "maps": list_of_map_translations}

        elif isinstance(selection_conditions, Mapping): 
            single_map_conditions = []
            for key, value in selection_conditions.items():
                single_map_conditions.extend(
                    translate_detection_item(key, value, category_mapping, unmapped_fields_set)
                )
            if single_map_conditions: 
                translated_detection[selection_name] = {"type": "map", "conditions": single_map_conditions}
    return translated_detection

def _build_pandas_query_from_condition_str(translated_condition_str, df, category):
    if "CONTAINS_ALL_PLACEHOLDER" in translated_condition_str:
        # print(f"Warning: CONTAINS_ALL_PLACEHOLDER found, should be pre-processed. Condition: {translated_condition_str}")
        return pd.Series(False, index=df.index)

    match = re.match(r"SIGMA_FIELD\('([^']+)'\) (?:CSV_COLUMN\('([^']+)'\)|UNMAPPED_FIELD\('([^']+)'\)|NO_CSV_MAPPING_FOR\('([^']+)'\)) (EQUALS|CONTAINS|STARTSWITH|ENDSWITH|IS_EMPTY_STRING|IS_NULL|REGEX|CIDR) ?(.*)?", translated_condition_str)
 
    if not match:
        return pd.Series(False, index=df.index)
 
    sigma_field_name = match.group(1)
    csv_col_name_from_match = match.group(2)
    unmapped_field_name = match.group(3)
    no_csv_mapping_field_name = match.group(4)
    operator = match.group(5)
    value_json_str = match.group(6)

    if unmapped_field_name or no_csv_mapping_field_name:
        return pd.Series(False, index=df.index)

    base_column_name = csv_col_name_from_match
    if base_column_name not in df.columns:
        return pd.Series(False, index=df.index)

    try:
        value = json.loads(value_json_str) if value_json_str else None
    except json.JSONDecodeError:
        return pd.Series(False, index=df.index)

    series_to_test = None
    data_is_full_path = False

    is_path_sensitive_operator = operator in ["STARTSWITH", "ENDSWITH", "CONTAINS"]
    rule_value_is_path_like = isinstance(value, str) and re.search(r"[\\/:]", value)

    if is_path_sensitive_operator and rule_value_is_path_like:
        path_components_info = PATH_COMPONENT_MAP.get(category, {}).get(sigma_field_name)
        if path_components_info:
            folder_col_name = path_components_info.get('folder')
            file_col_name = path_components_info.get('file')

            if folder_col_name and file_col_name and folder_col_name in df.columns and file_col_name in df.columns:
                def robust_join_paths(row_series, folder_column, file_column):
                    folder_val = str(row_series[folder_column]) if pd.notna(row_series[folder_column]) else ''
                    file_val = str(row_series[file_column]) if pd.notna(row_series[file_column]) else ''
                    if folder_val == 'nan': folder_val = ''
                    if file_val == 'nan': file_val = ''
                    if not folder_val and not file_val: return pd.NA
                    if not file_val: return folder_val
                    if not folder_val: return file_val
                    folder_val_lower = folder_val.lower()
                    file_val_lower = file_val.lower()
                    common_exec_extensions = ['.exe', '.dll', '.sys', '.com', '.bat', '.ps1', '.vbs', '.scr']
                    if folder_val_lower.endswith(file_val_lower) or \
                       any(folder_val_lower.endswith(ext) for ext in common_exec_extensions):
                        return folder_val 
                    return os.path.join(folder_val, file_val)
                series_to_test = df.apply(robust_join_paths, args=(folder_col_name, file_col_name), axis=1).astype(str).replace('nan', pd.NA)
                data_is_full_path = True

    if series_to_test is None:
        series_to_test = df[base_column_name].astype(str).replace('nan', pd.NA)
        data_is_full_path = False 

    rule_value_for_comp = str(value) if value is not None else None
    data_series_for_comp = series_to_test.str.lower() if series_to_test.dtype == 'object' or series_to_test.dtype == 'string' else series_to_test
    rule_value_lower_for_comp = rule_value_for_comp.lower() if isinstance(rule_value_for_comp, str) else rule_value_for_comp

    if operator == "EQUALS":
        if isinstance(value, str): return data_series_for_comp == rule_value_lower_for_comp 
        else: return series_to_test == rule_value_for_comp
    elif operator == "CONTAINS":
        if not isinstance(value, str): return pd.Series(False, index=df.index)
        return data_series_for_comp.str.contains(rule_value_lower_for_comp, case=False, na=False, regex=False)
    elif operator == "STARTSWITH":
        if not isinstance(value, str): return pd.Series(False, index=df.index)
        return data_series_for_comp.str.startswith(rule_value_lower_for_comp, na=False)
    elif operator == "ENDSWITH":
        if not isinstance(value, str): return pd.Series(False, index=df.index)
        if data_is_full_path: 
            return data_series_for_comp.str.endswith(rule_value_lower_for_comp, na=False)
        else: 
            def custom_endswith_filename_only(series_val_lower_str, rule_val_lower_str_param):
                if pd.isna(series_val_lower_str): return False
                if (rule_val_lower_str_param.startswith('\\') or rule_val_lower_str_param.startswith('/')) and \
                   '\\' not in series_val_lower_str and '/' not in series_val_lower_str: 
                    return series_val_lower_str.endswith(rule_val_lower_str_param[1:])
                return series_val_lower_str.endswith(rule_val_lower_str_param)
            return data_series_for_comp.apply(custom_endswith_filename_only, args=(rule_value_lower_for_comp,))
    elif operator == "IS_EMPTY_STRING": return series_to_test == ""
    elif operator == "IS_NULL": return series_to_test.isna()
    elif operator == "REGEX":
        try:
            # Suppress UserWarning for regex with match groups when only boolean result is needed
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                return series_to_test.str.contains(str(value), case=False, na=False, regex=True)
        except re.error: return pd.Series(False, index=df.index)
    elif operator == "CIDR":
        try:
            network = ipaddress.ip_network(value, strict=False)
            def ip_in_network(ip_str):
                if pd.isna(ip_str) or ip_str == '': return False
                try: return ipaddress.ip_address(ip_str) in network
                except ValueError: return False
            return series_to_test.apply(ip_in_network)
        except ValueError: return pd.Series(False, index=df.index)
    else: return pd.Series(False, index=df.index)

def _get_matching_selection_names(pattern, all_selection_names):
    if pattern == "them": return [s_name for s_name in all_selection_names]
    elif pattern.endswith("*"):
        prefix = pattern[:-1]
        return [s_name for s_name in all_selection_names if s_name.startswith(prefix)]
    elif pattern in all_selection_names: return [pattern]
    return []

def tokenize_condition(condition_str):
    normalized_condition = condition_str
    for char_or_op in ['(', ')', 'and', 'or', 'not']:
        if char_or_op in ['and', 'or', 'not']: 
            normalized_condition = re.sub(r'\b' + re.escape(char_or_op) + r'\b', f' {char_or_op} ', normalized_condition, flags=re.IGNORECASE)
        else: 
            normalized_condition = normalized_condition.replace(char_or_op, f' {char_or_op} ')
    normalized_condition = re.sub(r'\s+', ' ', normalized_condition).strip()
    raw_tokens = normalized_condition.split(' ')
    processed_tokens = []
    i = 0
    while i < len(raw_tokens):
        token = raw_tokens[i]
        if (token.lower() == 'all' or token.isdigit()) and \
           i + 2 < len(raw_tokens) and \
           raw_tokens[i+1].lower() == 'of':
            target_selection_pattern = raw_tokens[i+2]
            if target_selection_pattern.endswith('*') or target_selection_pattern.lower() == 'them':
                processed_tokens.append(f"{token} {raw_tokens[i+1]} {target_selection_pattern}")
                i += 3 
                continue
        processed_tokens.append(token)
        i += 1
    final_tokens = [t.upper() if t.lower() in ['and', 'or', 'not'] else t for t in processed_tokens]
    return final_tokens

def _evaluate_quantifier_token(quantifier_token_str, selection_series_map, df_index):
    parts = quantifier_token_str.split(' ')
    if len(parts) != 3 or parts[1].lower() != 'of': return pd.Series(False, index=df_index)
    quantifier_val_str = parts[0].lower()
    pattern = parts[2]
    matching_names = _get_matching_selection_names(pattern, list(selection_series_map.keys()))
    if not matching_names: return pd.Series(False, index=df_index)
    series_to_combine = [selection_series_map.get(name, pd.Series(False, index=df_index)).reindex(df_index, fill_value=False) for name in matching_names]
    if not series_to_combine: return pd.Series(False, index=df_index)
    if quantifier_val_str == 'all':
        return reduce(lambda x, y: x & y, series_to_combine) if series_to_combine else pd.Series(True, index=df_index)
    elif quantifier_val_str.isdigit():
        num_required = int(quantifier_val_str)
        if num_required == 0: return pd.Series(True, index=df_index) if series_to_combine else pd.Series(False, index=df_index)
        if num_required == 1 and len(series_to_combine) > 0: return reduce(lambda x, y: x | y, series_to_combine)
        else:
            df_temp = pd.concat(series_to_combine, axis=1)
            return df_temp.sum(axis=1) >= num_required
    else: return pd.Series(False, index=df_index)
 
def _get_operator_precedence(op):
    if op == 'NOT': return 3
    if op == 'AND': return 2
    if op == 'OR':  return 1
    return 0

def infix_to_rpn(tokens):
    output_queue, operator_stack = [], []
    for token in tokens:
        if token not in ['AND', 'OR', 'NOT', '(', ')']: output_queue.append(token)
        elif token == '(': operator_stack.append(token)
        elif token == ')':
            while operator_stack and operator_stack[-1] != '(': output_queue.append(operator_stack.pop())
            if not operator_stack or operator_stack[-1] != '(': raise ValueError("Mismatched parentheses")
            operator_stack.pop() 
        else: 
            while (operator_stack and operator_stack[-1] != '(' and
                   _get_operator_precedence(operator_stack[-1]) >= _get_operator_precedence(token)):
                output_queue.append(operator_stack.pop())
            operator_stack.append(token)
    while operator_stack:
        if operator_stack[-1] == '(': raise ValueError("Mismatched parentheses")
        output_queue.append(operator_stack.pop())
    return output_queue

def evaluate_rpn(rpn_tokens, selection_series_map, quantifier_results_map, df_index):
    value_stack = []
    for token in rpn_tokens:
        if token == 'AND':
            if len(value_stack) < 2: raise ValueError("RPN: insufficient operands for AND")
            op2, op1 = value_stack.pop(), value_stack.pop()
            value_stack.append(op1 & op2)
        elif token == 'OR':
            if len(value_stack) < 2: raise ValueError("RPN: insufficient operands for OR")
            op2, op1 = value_stack.pop(), value_stack.pop()
            value_stack.append(op1 | op2)
        elif token == 'NOT':
            if len(value_stack) < 1: raise ValueError("RPN: insufficient operand for NOT")
            op = value_stack.pop()
            value_stack.append(~op)
        else: 
            if token in selection_series_map:
                value_stack.append(selection_series_map[token].reindex(df_index, fill_value=False))
            elif token in quantifier_results_map:
                value_stack.append(quantifier_results_map[token].reindex(df_index, fill_value=False))
            else: value_stack.append(pd.Series(False, index=df_index))
    if len(value_stack) != 1: raise ValueError(f"RPN: stack ended with {len(value_stack)} values")
    return value_stack[0]

# --- Main application function ---
def apply_sigma_rule_to_csv(sigma_rule_path, csv_file_path, field_mapping_file_path):
    field_mappings = load_field_mapping(field_mapping_file_path)
    if not field_mappings:
        return None, "Error: Field mapping file not found or failed to load", "N/A", "N/A", set()

    sigma_rule = parse_sigma_rule(sigma_rule_path)
    if not sigma_rule:
        return None, "Error: Rule parsing failed", "N/A", "N/A", set()

    rule_title_for_debug = sigma_rule.get('title', "N/A")
    sigma_rule_level = sigma_rule.get('level', 'informational') # Extract rule level, default to informational
    # For general debug prints related to a specific rule's filter logic
    debug_rule_id_generic_filter_target = None # Set to a specific rule ID to enable these prints
    print_generic_filter_debug_flag = (sigma_rule.get('id') == debug_rule_id_generic_filter_target)

    logsource = sigma_rule.get('logsource', {})
    category = logsource.get('category')
    if not category:
        return None, rule_title_for_debug + " - Error: Missing logsource.category", sigma_rule.get('id', 'N/A'), sigma_rule_level, set()
    
    unmapped_fields = set()
    category_mapping = field_mappings.get(category)
    if not category_mapping:
        return None, rule_title_for_debug + f" - Error: No field mapping for category '{category}'", sigma_rule.get('id', 'N/A'), sigma_rule_level, unmapped_fields

    detection = sigma_rule.get('detection', {})
    if not detection:
        return pd.DataFrame(), rule_title_for_debug, sigma_rule.get('id', 'N/A'), sigma_rule_level, unmapped_fields
        
    detection_condition_str = detection.get('condition')
    if not detection_condition_str:
        return pd.DataFrame(), rule_title_for_debug + " - Warning: No detection condition", sigma_rule.get('id', 'N/A'), sigma_rule_level, unmapped_fields
 
    translated_logic = translate_detection_section(detection, category_mapping, unmapped_fields)
 
    try:
        df_full = pd.read_csv(csv_file_path, low_memory=False)
    except FileNotFoundError:
        return None, rule_title_for_debug + f" - Error: CSV file '{csv_file_path}' not found.", sigma_rule.get('id', 'N/A'), sigma_rule_level, unmapped_fields
    except Exception as e:
        return None, rule_title_for_debug + f" - Error reading CSV: {e}", sigma_rule.get('id', 'N/A'), sigma_rule_level, unmapped_fields
        
    if df_full.empty:
        return pd.DataFrame(), rule_title_for_debug, sigma_rule.get('id', 'N/A'), sigma_rule_level, unmapped_fields
 
    df = df_full 
    action_type_map = field_mappings.get("_logsource_category_to_action_type_", {})
    csv_action_types_for_category = action_type_map.get(category)
 
    if csv_action_types_for_category:
        if 'Action Type' in df.columns:
            if isinstance(csv_action_types_for_category, list):
                df = df[df['Action Type'].isin(csv_action_types_for_category)]
            else: 
                df = df[df['Action Type'] == csv_action_types_for_category]
            if df.empty:
                return pd.DataFrame(), rule_title_for_debug, sigma_rule.get('id', 'N/A'), sigma_rule_level, unmapped_fields
        # else: 'Action Type' column not in CSV, cannot pre-filter
            
    if df.empty:
        return pd.DataFrame(), rule_title_for_debug, sigma_rule.get('id', 'N/A'), sigma_rule_level, unmapped_fields
 
    selection_series_map = {}
    for sel_name, logic_structure in translated_logic.items():
        if not logic_structure or \
           (logic_structure["type"] == "map" and not logic_structure.get("conditions")) or \
           (logic_structure["type"] == "list_of_maps" and not logic_structure.get("maps")):
            selection_series_map[sel_name] = pd.Series(False, index=df.index)
            continue

        if logic_structure["type"] == "map":
            cond_list = logic_structure["conditions"]
            current_selection_series = pd.Series(True, index=df.index) 
            
            for i, cond_str in enumerate(cond_list):
                individual_cond_series = pd.Series(False, index=df.index)
                if cond_str.startswith("(") and cond_str.endswith(")") and " OR " in cond_str:
                    or_group_str = cond_str[1:-1]
                    or_conditions = or_group_str.split(" OR ")
                    or_series_for_field = pd.Series(False, index=df.index)
                    for or_c_idx, or_c in enumerate(or_conditions):
                        temp_or_series = _build_pandas_query_from_condition_str(or_c.strip(), df, category)
                        or_series_for_field |= temp_or_series
                    individual_cond_series = or_series_for_field
                else:
                    individual_cond_series = _build_pandas_query_from_condition_str(cond_str, df, category)
                current_selection_series &= individual_cond_series
            selection_series_map[sel_name] = current_selection_series

        elif logic_structure["type"] == "list_of_maps":
            overall_or_series = pd.Series(False, index=df.index) 
            map_translations_list = logic_structure["maps"]

            for map_internal_cond_list in map_translations_list:
                if not map_internal_cond_list: 
                    continue 
                current_map_series = pd.Series(True, index=df.index) 
                for cond_str in map_internal_cond_list:
                    if cond_str.startswith("(") and cond_str.endswith(")") and " OR " in cond_str:
                        or_group_str = cond_str[1:-1]
                        or_conditions = or_group_str.split(" OR ")
                        or_series_for_field = pd.Series(False, index=df.index)
                        for or_c in or_conditions:
                            or_series_for_field |= _build_pandas_query_from_condition_str(or_c.strip(), df, category) 
                        current_map_series &= or_series_for_field
                    else:
                        current_map_series &= _build_pandas_query_from_condition_str(cond_str, df, category) 
                overall_or_series |= current_map_series 
            selection_series_map[sel_name] = overall_or_series
            
    infix_tokens = tokenize_condition(detection_condition_str)
    processed_infix_tokens = []
    quantifier_results_map = {} 
    quant_idx = 0
    for token in infix_tokens:
        if (" of " in token.lower() and (token.lower().startswith("all of ") or token.lower()[0].isdigit())): 
            quant_placeholder = f"__QUANT_RESULT_{quant_idx}__"
            quant_series = _evaluate_quantifier_token(token, selection_series_map, df.index)
            quantifier_results_map[quant_placeholder] = quant_series
            processed_infix_tokens.append(quant_placeholder)
            quant_idx += 1
        else:
            processed_infix_tokens.append(token)
            
    try:
        rpn_tokens = infix_to_rpn(processed_infix_tokens)
        final_filter = evaluate_rpn(rpn_tokens, selection_series_map, quantifier_results_map, df.index)

    except ValueError as e:
        final_filter = pd.Series(False, index=df.index)
        return pd.DataFrame(), rule_title_for_debug + f" - RPN/Eval Error: {e}", sigma_rule.get('id', 'N/A'), sigma_rule_level, unmapped_fields
    except Exception as e:
        final_filter = pd.Series(False, index=df.index)
        return pd.DataFrame(), rule_title_for_debug + f" - Unexpected Eval Error: {e}", sigma_rule.get('id', 'N/A'), sigma_rule_level, unmapped_fields
 
    matching_rows_from_filtered_df = df[final_filter]
 
    if df is not df_full and not matching_rows_from_filtered_df.empty:
        original_indices = matching_rows_from_filtered_df.index
        matching_rows = df_full.loc[original_indices].copy()
        if not matching_rows.empty:
            matching_rows['Sigma Rule Level'] = sigma_rule_level
    elif not matching_rows_from_filtered_df.empty:
        matching_rows = matching_rows_from_filtered_df.copy()
        if not matching_rows.empty:
            matching_rows['Sigma Rule Level'] = sigma_rule_level
    else:
        matching_rows = pd.DataFrame()
    
    return matching_rows, rule_title_for_debug, sigma_rule.get('id', 'N/A'), sigma_rule_level, unmapped_fields

def main():
    # Get the directory of the current script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    default_mapping_path = os.path.join(script_dir, "field_mapping.json")

    parser = argparse.ArgumentParser(description="Apply a translated Sigma rule to a CSV file and print results.")
    parser.add_argument("sigma_rule_path", help="Path to the Sigma rule .yml file.")
    parser.add_argument("--csv", required=True, dest="csv_file_path",
                        help="Path to the CSV data file.")
    parser.add_argument("--mapping", default=default_mapping_path, dest="mapping_file_path",
                        help=f"Path to the field mapping JSON file (default: {default_mapping_path}).")
    
    args = parser.parse_args()

    if not os.path.exists(args.sigma_rule_path):
        print(f"Error: Sigma rule file not found: {args.sigma_rule_path}")
        return
    if not os.path.exists(args.csv_file_path):
        print(f"Error: CSV file not found: {args.csv_file_path}")
        return
    if not os.path.exists(args.mapping_file_path):
        print(f"Error: Mapping file not found: {args.mapping_file_path}")
        return
        
    matching_df, rule_title, rule_id, rule_level, unmapped_fields_found = apply_sigma_rule_to_csv(
        args.sigma_rule_path,
        args.csv_file_path,
        args.mapping_file_path
    )
    
    if matching_df is not None and not matching_df.empty:
        # Rule level is already in matching_df if matches were found
        print(f"\n--- Direct Execution Results for Rule ID: {rule_id} ({rule_title}) ---")
        print(matching_df.to_string())
    elif matching_df is not None: 
        print(f"\n--- Direct Execution Results for Rule ID: {rule_id} ({rule_title}) - No matches found. ---")
    
    if unmapped_fields_found:
        print(f"Unmapped fields encountered during processing: {', '.join(sorted(list(unmapped_fields_found)))}")

if __name__ == "__main__":
    main()