import os
import yaml
import json
from collections.abc import Mapping, Sequence

def extract_fields_from_detection(data, current_fields):
    """
    Recursively extracts field names from a Sigma rule's detection dictionary.
    Handles keys with modifiers (e.g., 'Image|endswith').
    """
    if isinstance(data, Mapping):
        for key, value in data.items():
            # Field names can have modifiers like Image|endswith, CommandLine|contains
            # We only want the base field name (e.g., "Image", "CommandLine")
            base_key = key.split('|')[0]
            if base_key not in ['condition', 'timeframe', 'timespan', 'timeoffset', 'keywords', 'falsepositives', 'description', 'level', 'status', 'id', 'title', 'author', 'references', 'tags', 'logsource', 'related', 'detection', 'fields', 'groupby']: # common sigma keys that are not event fields
                current_fields.add(base_key)
            if isinstance(value, (Mapping, Sequence)):
                extract_fields_from_detection(value, current_fields)
    elif isinstance(data, Sequence) and not isinstance(data, str):
        for item in data:
            if isinstance(item, (Mapping, Sequence)):
                extract_fields_from_detection(item, current_fields)
            # Sometimes, a list might contain simple strings that are meant to be field names
            # in specific contexts, but usually fields are keys in mappings.
            # This part might need refinement based on diverse Sigma rule structures.
            # For now, focusing on keys from mappings.

def main():
    sigma_root_dir = 'sigma'
    all_detection_fields = set()
    all_logsource_categories = set()
    all_logsource_products = set()
    all_logsource_services = set()
    parsed_rule_count = 0
    error_rule_count = 0

    # Exclude common non-rule directories and specific files/extensions
    excluded_dirs = {'deprecated', 'documentation', 'images', 'other', 'tests', 'rules-compliance', 'rules-dfir', 'rules-placeholder', 'tools'}
    excluded_files_or_ext = {'.py', '.sh', '.md', '.json', '.txt', '.csv', 'CODE_OF_CONDUCT.md', 'LICENSE.md', 'Makefile', 'README.md'}


    for root, dirs, files in os.walk(sigma_root_dir):
        # Modify dirs in-place to skip excluded directories
        dirs[:] = [d for d in dirs if d not in excluded_dirs]

        for file in files:
            if file.endswith('.yml'):
                # Further filter out files that are unlikely to be rules
                if file in excluded_files_or_ext or any(file.endswith(ext) for ext in excluded_files_or_ext if ext.startswith('.')):
                    continue

                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        rule_content_str = f.read()
                        # Quick check for essential Sigma rule keys before full parse
                        if not ('title:' in rule_content_str and \
                                'logsource:' in rule_content_str and \
                                'detection:' in rule_content_str):
                            # print(f"Skipping non-Sigma file (missing essential keys): {file_path}")
                            continue

                        # Reset stream position for PyYAML
                        f.seek(0)
                        rule = yaml.safe_load(f)

                        if not isinstance(rule, dict):
                            # print(f"Skipping non-dictionary YAML: {file_path}")
                            continue

                        # Check for essential Sigma rule keys
                        if 'title' not in rule or 'logsource' not in rule or 'detection' not in rule:
                            # print(f"Skipping file (missing essential Sigma keys after parse): {file_path}")
                            continue

                        # Extract logsource info
                        logsource = rule.get('logsource', {})
                        if isinstance(logsource, dict):
                            category = logsource.get('category')
                            product = logsource.get('product')
                            service = logsource.get('service')
                            if category:
                                all_logsource_categories.add(str(category))
                            if product:
                                all_logsource_products.add(str(product))
                            if service:
                                all_logsource_services.add(str(service))

                        # Extract detection fields
                        detection_data = rule.get('detection')
                        if detection_data:
                            current_rule_fields = set()
                            extract_fields_from_detection(detection_data, current_rule_fields)
                            all_detection_fields.update(current_rule_fields)
                        
                        parsed_rule_count += 1

                except yaml.YAMLError as e:
                    print(f"Error parsing YAML in {file_path}: {e}")
                    error_rule_count += 1
                except Exception as e:
                    print(f"An unexpected error occurred with {file_path}: {e}")
                    error_rule_count += 1
    
    output_data = {
        'detection_fields': sorted(list(all_detection_fields)),
        'logsource_categories': sorted(list(all_logsource_categories)),
        'logsource_products': sorted(list(all_logsource_products)),
        'logsource_services': sorted(list(all_logsource_services)),
        'statistics': {
            'total_yml_files_processed_as_rules': parsed_rule_count,
            'rules_with_parsing_errors': error_rule_count
        }
    }

    output_file_path = 'extracted_sigma_data.json'
    with open(output_file_path, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=4)

    print(f"Extraction complete. Data saved to {output_file_path}")
    print(f"Processed {parsed_rule_count} rules successfully.")
    print(f"Encountered errors in {error_rule_count} files.")

if __name__ == '__main__':
    main()