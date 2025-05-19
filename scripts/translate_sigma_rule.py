import yaml
import json
import argparse
import os
import re # For parsing condition string
from collections.abc import Mapping, Sequence

def load_field_mapping(mapping_file_path=None):
    """Loads the field mapping JSON file."""
    if mapping_file_path is None:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        mapping_file_path = os.path.join(script_dir, "field_mapping.json")

    if not os.path.exists(mapping_file_path):
        print(f"Error: Mapping file '{mapping_file_path}' not found.")
        return None
    with open(mapping_file_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def parse_sigma_rule(rule_file_path):
    """Parses a Sigma rule YAML file."""
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

def translate_detection_item(item_key, item_value, category_mapping, unmapped_fields):
    """
    Translates a single detection item (key-value pair) from a Sigma rule.
    item_key: e.g., 'Image|endswith' or 'CommandLine'
    item_value: e.g., '\curl.exe' or ['-o', '-output']
    category_mapping: The specific mapping for the rule's logsource category.
    """
    translated_conditions = []
    sigma_field_base = item_key.split('|')[0]
    sigma_modifier = item_key.split('|')[1] if '|' in item_key else None

    condition_prefix = ""
    # mapped_to_none = False # Not strictly needed here anymore

    if sigma_field_base in category_mapping:
        csv_column = category_mapping[sigma_field_base]
        if csv_column is None:
            condition_prefix = f"NO_CSV_MAPPING_FOR('{sigma_field_base}')"
            # mapped_to_none = True
        else:
            condition_prefix = f"CSV_COLUMN('{csv_column}')"
    else:
        unmapped_fields.add(sigma_field_base)
        condition_prefix = f"UNMAPPED_FIELD('{sigma_field_base}')"

    if sigma_modifier:
        if isinstance(item_value, list): 
            conditions = [f"{condition_prefix} {sigma_modifier.upper()} {json.dumps(v)}" for v in item_value]
            translated_conditions.append(f"({' OR '.join(conditions)})") 
        else:
            translated_conditions.append(f"{condition_prefix} {sigma_modifier.upper()} {json.dumps(item_value)}")
    else:
        if isinstance(item_value, list):
            conditions = [f"{condition_prefix} EQUALS {json.dumps(v)}" for v in item_value]
            translated_conditions.append(f"({' OR '.join(conditions)})")
        elif isinstance(item_value, str) and item_value == '':
            translated_conditions.append(f"{condition_prefix} IS_EMPTY_STRING")
        elif item_value is None:
            translated_conditions.append(f"{condition_prefix} IS_NULL")
        else:
            translated_conditions.append(f"{condition_prefix} EQUALS {json.dumps(item_value)}")
            
    return translated_conditions

def translate_detection_section(detection_dict, category_mapping, unmapped_fields):
    """
    Recursively translates the detection section of a Sigma rule.
    Returns a dictionary of translated selection conditions.
    """
    translated_detection = {}
    if not isinstance(detection_dict, Mapping):
        return translated_detection

    for selection_name, selection_conditions in detection_dict.items():
        if selection_name == 'condition':
            continue 

        translated_selection_conditions = []
        if isinstance(selection_conditions, list): 
            for condition_item in selection_conditions:
                if isinstance(condition_item, Mapping): 
                    for key, value in condition_item.items():
                        translated_selection_conditions.extend(
                            translate_detection_item(key, value, category_mapping, unmapped_fields)
                        )
        elif isinstance(selection_conditions, Mapping): 
             for key, value in selection_conditions.items():
                translated_selection_conditions.extend(
                    translate_detection_item(key, value, category_mapping, unmapped_fields)
                )
        
        translated_detection[selection_name] = translated_selection_conditions
    return translated_detection

def format_selection_logic(selection_name, conditions_list):
    """Formats the conditions for a single selection."""
    if not conditions_list:
        return f"  (Selection '{selection_name}' has no translatable conditions or is empty)"
    
    # Conditions within a named selection are typically ANDed unless they come from a list of values in Sigma
    # For example, `field|modifier: [val1, val2]` becomes `(field mod val1 OR field mod val2)`
    # If a selection is `field1: val1\nfield2: val2`, these are ANDed.
    # Our current translate_detection_item already creates OR groups for lists of values.
    # So, multiple strings in conditions_list for a single selection are effectively ANDed.
    
    formatted_conditions = f"\n    AND ".join(conditions_list)
    return f"  (Selection '{selection_name}':\n    {formatted_conditions}\n  )"

def format_translated_condition(condition_str, translated_logic, raw_detection_dict):
    """
    Formats the output based on the Sigma condition string.
    raw_detection_dict is the original detection dictionary from the Sigma rule.
    """
    output_lines = ["  Overall Condition Logic:"]
    
    # Step 1: Tokenize the condition string more robustly
    # This regex captures:
    # - Numbers followed by 'of' (e.g., '1 of')
    # - 'all of' pattern
    # - Selection names with optional wildcards (e.g., 'selection_*')
    # - Boolean operators (and, or, not)
    # - Parentheses
    # - Other special characters
    
    # First, normalize the condition string to ensure spaces around operators and parentheses
    normalized_condition = condition_str
    for char in ['(', ')', 'and', 'or', 'not']:
        if char in ['and', 'or', 'not']:
            normalized_condition = re.sub(r'\b' + re.escape(char) + r'\b', f' {char} ', normalized_condition)
        else:
            normalized_condition = normalized_condition.replace(char, f' {char} ')
    normalized_condition = re.sub(r'\s+', ' ', normalized_condition).strip()
    
    # Now tokenize the normalized condition
    tokens = []
    i = 0
    words = normalized_condition.split()
    while i < len(words):
        word = words[i]
        
        # Handle 'all of X' pattern
        if word == 'all' and i + 2 < len(words) and words[i+1] == 'of':
            target = words[i+2]
            # Check if the target has a wildcard suffix
            if target.endswith('*'):
                tokens.append(f"all of {target}")
            else:
                tokens.append('all of')
                tokens.append(target)
            i += 3
            continue
            
        # Handle 'X of Y' pattern (where X is a number)
        if word.isdigit() and i + 2 < len(words) and words[i+1] == 'of':
            target = words[i+2]
            # Check if the target has a wildcard suffix
            if target.endswith('*'):
                tokens.append(f"{word} of {target}")
            else:
                tokens.append(f"{word} of")
                tokens.append(target)
            i += 3
            continue
            
        # Handle boolean operators
        if word in ['and', 'or', 'not']:
            tokens.append(word.upper())
            i += 1
            continue
            
        # Handle parentheses
        if word in ['(', ')']:
            tokens.append(word)
            i += 1
            continue
            
        # Handle selection names (possibly with wildcards)
        tokens.append(word)
        i += 1
    
    # Step 2: Process tokens and build the output
    display_condition_str = " ".join(tokens)
    output_lines.append(f"  Condition: {display_condition_str}")
    
    # Store details of selections/groups to define later
    definitions_to_print = {}
    
    # Step 3: Process each token to build definitions
    i = 0
    while i < len(tokens):
        token = tokens[i]
        
        # Handle "all of X" pattern
        if token.startswith("all of "):
            pattern = token.split(" ", 2)[2]  # e.g., "selection_*" or "them"
            display_condition_str = process_quantifier_pattern(
                pattern, "ALL", raw_detection_dict, translated_logic,
                definitions_to_print, display_condition_str, token
            )
            
        # Handle "X of Y" pattern
        elif re.match(r'^\d+\s+of\s+', token):
            parts = token.split(" ", 2)
            count = parts[0]
            pattern = parts[2]  # e.g., "selection_*" or "them"
            display_condition_str = process_quantifier_pattern(
                pattern, count, raw_detection_dict, translated_logic,
                definitions_to_print, display_condition_str, token
            )
            
        # Handle individual selections
        elif token in translated_logic and not any(token in d for d in definitions_to_print.values()):
            placeholder = f"__LOGIC_FOR_{token.upper()}__"
            definitions_to_print[placeholder] = format_selection_logic(token, translated_logic[token])
            # Replace the token with its placeholder in display_condition_str
            display_condition_str = re.sub(r'\b' + re.escape(token) + r'\b', placeholder, display_condition_str)
            
        i += 1
    
    # Update the condition display line with the processed condition
    output_lines[1] = f"  Condition: {display_condition_str}"
    
    # Add definitions to the output
    if definitions_to_print:
        output_lines.append("\n  Where:")
        
        # Sort placeholders to show quantifiers first
        sorted_placeholders = sorted(definitions_to_print.keys(),
                                    key=lambda x: (not ("ALL_OF_" in x or "_OF_" in x), x))
        
        for placeholder in sorted_placeholders:
            logic_str = definitions_to_print[placeholder]
            is_referenced = placeholder in display_condition_str
            
            # Check if the original selection name is still in the display condition
            if not is_referenced and placeholder.startswith("__LOGIC_FOR_"):
                original_name = placeholder.replace("__LOGIC_FOR_", "").lower()
                if re.search(r'\b' + re.escape(original_name) + r'\b', display_condition_str, re.IGNORECASE):
                    is_referenced = True
            
            if is_referenced:
                output_lines.append(f"\n  {placeholder} IS:\n{logic_str}")
    
    # Check if we made a meaningful translation
    made_meaningful_translation = any(p in display_condition_str for p in definitions_to_print.keys())
    
    if not made_meaningful_translation:
        if condition_str != display_condition_str:
            output_lines.append(f"\n  (Note: Condition was modified from '{condition_str}' to '{display_condition_str}', but detailed expansion failed or was not applicable.)")
        else:
            output_lines.append(f"\n  (Note: Condition '{condition_str}' was not expanded by current logic.)")
    
    return "\n".join(output_lines)

def process_quantifier_pattern(pattern, count, raw_detection_dict, translated_logic, definitions_to_print, display_condition_str, token_item):
    """
    Helper function to process 'all of X' or 'X of Y' patterns.
    
    Args:
        pattern: The pattern to match (e.g., 'selection_*', 'them')
        count: The count or 'ALL' for 'all of'
        raw_detection_dict: The original detection dictionary
        translated_logic: The translated detection logic
        definitions_to_print: Dictionary to store definitions
        display_condition_str: The display condition string
        token_item: The original token
    """
    group_conditions = []
    count_str = "ALL" if count == "ALL" else count
    group_name_for_display = f"{count_str}_OF_{pattern.replace('*','WILDCARD').upper()}"
    
    # Determine which selections to include
    selections_to_iterate = []
    if pattern == "them":  # "all of them" or "X of them"
        selections_to_iterate = [s for s in raw_detection_dict.keys() if s != 'condition']
    elif pattern.endswith("*"):
        prefix = pattern[:-1]  # e.g., "selection_" from "selection_*"
        selections_to_iterate = [s for s in raw_detection_dict.keys()
                                if s.startswith(prefix) and s != 'condition']
    
    # Process each matching selection
    for sel_name in selections_to_iterate:
        if sel_name in translated_logic and translated_logic[sel_name]:
            group_conditions.append(format_selection_logic(sel_name, translated_logic[sel_name]))
        elif sel_name in translated_logic:
            group_conditions.append(f"  (Selection '{sel_name}' has no translatable conditions or is empty)")
    
    # Add the definition to the dictionary
    if group_conditions:
        if count == "ALL":
            definitions_to_print[group_name_for_display] = "ALL OF THE FOLLOWING MUST BE TRUE:\n" + "\n".join(group_conditions)
        else:
            definitions_to_print[group_name_for_display] = f"AT LEAST {count} OF THE FOLLOWING MUST BE TRUE:\n" + "\n".join(group_conditions)
    else:
        definitions_to_print[group_name_for_display] = f"  (No selections found or translated for '{token_item}')"
    
    # Replace the token with its placeholder in the display condition string
    display_condition_str = display_condition_str.replace(token_item, group_name_for_display)


def main():
    parser = argparse.ArgumentParser(description="Translate a Sigma rule to CSV-based logic.")
    parser.add_argument("rule_file", help="Path to the Sigma rule .yml file.")
    args = parser.parse_args()

    field_mappings = load_field_mapping()
    if not field_mappings:
        return

    sigma_rule = parse_sigma_rule(args.rule_file)
    if not sigma_rule:
        return

    print(f"--- Translating Sigma Rule: {sigma_rule.get('title', 'N/A')} ---")
    print(f"ID: {sigma_rule.get('id', 'N/A')}\n")

    logsource = sigma_rule.get('logsource', {})
    category = logsource.get('category')

    if not category:
        print("Error: Sigma rule does not have a 'logsource.category'. Cannot determine mapping.")
        return

    category_mapping = field_mappings.get(category)
    if not category_mapping:
        print(f"Error: No field mapping found for category '{category}'.")
        print(f"Available categories in mapping: {list(field_mappings.keys())}")
        return

    print(f"Using mapping for category: '{category}'\n")

    detection = sigma_rule.get('detection', {})
    if not detection:
        print("Warning: Sigma rule has no 'detection' section.")
        return

    print("Original Sigma Detection Logic:")
    print(yaml.dump({'detection': detection}, indent=2, sort_keys=False))

    unmapped_fields = set()
    translated_detection_logic = translate_detection_section(detection, category_mapping, unmapped_fields)

    print("\nTranslated CSV-based Logic:")
    if 'condition' in detection:
        condition_str = detection['condition']
        # Pass the raw detection dictionary to allow format_translated_condition to access selection names
        formatted_output = format_translated_condition(condition_str, translated_detection_logic, detection)
        print(formatted_output)
    else:
        # If no explicit condition, but there are selections, assume 'all of them' for now
        print("  Warning: No overall 'condition' field found in detection block. Displaying individual selections (implicitly ANDed if multiple):")
        for selection_name, conditions in translated_detection_logic.items():
            if conditions: 
                print(f"  Selection '{selection_name}':")
                for i, cond_str in enumerate(conditions):
                    print(f"    - {cond_str}")
    
    if unmapped_fields:
        print("\n--- Unmapped Sigma Fields ---")
        for field in sorted(list(unmapped_fields)):
            print(f"- {field}")
    
    print("\n--- End of Translation ---")

if __name__ == '__main__':
    main()