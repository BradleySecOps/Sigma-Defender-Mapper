import os
import yaml
import json
from collections import defaultdict, Counter
import re

def analyze_sigma_rules(base_dir="sigma"):
    """
    Analyze all Sigma rules in the repository to understand their structure and patterns.
    
    Args:
        base_dir: The base directory containing Sigma rules
        
    Returns:
        A dictionary with analysis results
    """
    results = {
        "logsource_categories": Counter(),
        "logsource_products": Counter(),
        "logsource_services": Counter(),
        "condition_patterns": Counter(),
        "detection_field_types_by_product_category": defaultdict(lambda: defaultdict(Counter)), # New structure
        "detection_field_types_by_category": defaultdict(Counter), # Keep old structure for general analysis
        "complex_conditions": [],
        "sample_rules_by_category": defaultdict(list),
        "wildcard_patterns": Counter(),
        "modifier_usage": Counter()
    }
    
    rule_count = 0
    
    # Walk through all directories in the base_dir
    for root, dirs, files in os.walk(base_dir):
        for file in files:
            if file.endswith(".yml"):
                rule_path = os.path.join(root, file)
                try:
                    with open(rule_path, 'r', encoding='utf-8') as f:
                        rule = yaml.safe_load(f)
                    
                    rule_count += 1
                    
                    # Extract logsource information
                    if "logsource" in rule:
                        logsource = rule["logsource"]
                        category = logsource.get("category")
                        product = logsource.get("product")
                        service = logsource.get("service")
                        
                        if category:
                            results["logsource_categories"][category] += 1
                            
                            # Store a sample rule for each category (up to 5)
                            if len(results["sample_rules_by_category"][category]) < 5:
                                results["sample_rules_by_category"][category].append({
                                    "path": rule_path,
                                    "title": rule.get("title", "Untitled"),
                                    "id": rule.get("id", "No ID")
                                })
                        
                        if product:
                            results["logsource_products"][product] += 1
                        
                        if service:
                            results["logsource_services"][service] += 1
                    
                    # Extract detection information
                    if "detection" in rule:
                        detection = rule["detection"]
                        
                        # Analyze condition patterns
                        if "condition" in detection:
                            condition = detection["condition"]
                            results["condition_patterns"][condition] += 1
                            
                            # Identify complex conditions
                            if any(pattern in condition for pattern in ["not", "1 of", "all of", "*"]):
                                results["complex_conditions"].append({
                                    "path": rule_path,
                                    "condition": condition,
                                    "title": rule.get("title", "Untitled")
                                })
                            
                            # Extract wildcard patterns
                            wildcard_matches = re.findall(r'\b\w+\s+of\s+\w+_\*', condition)
                            for match in wildcard_matches:
                                results["wildcard_patterns"][match] += 1
                        
                        # Analyze detection fields and modifiers
                        for selection_name, selection_content in detection.items():
                            if selection_name == "condition":
                                continue
                            
                            if isinstance(selection_content, dict):
                                for field, value in selection_content.items():
                                    field_base = field.split('|')[0]
                                    if '|' in field:
                                        modifier = field.split('|')[1]
                                        results["modifier_usage"][modifier] += 1
                                    
                                    # Track field types by category (old structure)
                                    if category:
                                        results["detection_field_types_by_category"][category][field_base] += 1
                                    
                                    # Track field types by product and then category (new structure)
                                    current_product = product if product else "_NO_PRODUCT_"
                                    current_category = category if category else "_NO_CATEGORY_"
                                    results["detection_field_types_by_product_category"][current_product][current_category][field_base] += 1
                            
                            elif isinstance(selection_content, list):
                                for item in selection_content:
                                    if isinstance(item, dict):
                                        for field, value in item.items():
                                            field_base = field.split('|')[0]
                                            if '|' in field:
                                                modifier = field.split('|')[1]
                                                results["modifier_usage"][modifier] += 1
                                            
                                            # Track field types by category (old structure)
                                            if category:
                                                results["detection_field_types_by_category"][category][field_base] += 1
                                            
                                            # Track field types by product and then category (new structure)
                                            current_product = product if product else "_NO_PRODUCT_"
                                            current_category = category if category else "_NO_CATEGORY_"
                                            results["detection_field_types_by_product_category"][current_product][current_category][field_base] += 1
                
                except Exception as e:
                    print(f"Error processing {rule_path}: {e}")
    
    # Convert defaultdicts to regular dicts for JSON serialization
    results["detection_field_types_by_category"] = {k: dict(v) for k, v in results["detection_field_types_by_category"].items()}
    
    product_category_dict = {}
    for prod, cat_dict in results["detection_field_types_by_product_category"].items():
        product_category_dict[prod] = {k: dict(v) for k, v in cat_dict.items()}
    results["detection_field_types_by_product_category"] = product_category_dict
    
    # Add total rule count
    results["total_rules"] = rule_count
    
    return results

def main():
    results = analyze_sigma_rules()
    
    # Save results to a JSON file
    with open("sigma_analysis_results.json", 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)
    
    # Print summary
    print(f"Analyzed {results['total_rules']} Sigma rules")
    print("\nTop 10 logsource categories:")
    for category, count in results["logsource_categories"].most_common(10):
        print(f"  {category}: {count} rules")
    
    print("\nTop 10 condition patterns:")
    for pattern, count in results["condition_patterns"].most_common(10):
        print(f"  '{pattern}': {count} rules")
    
    print("\nTop 10 field modifiers:")
    for modifier, count in results["modifier_usage"].most_common(10):
        print(f"  '{modifier}': {count} occurrences")
    
    print("\nTop 10 wildcard patterns:")
    for pattern, count in results["wildcard_patterns"].most_common(10):
        print(f"  '{pattern}': {count} occurrences")
    
    print("\nComplex condition examples (first 5):")
    for i, condition in enumerate(results["complex_conditions"][:5]):
        print(f"  {i+1}. '{condition['condition']}' in {condition['title']}")
    
    print("\nDetailed results saved to sigma_analysis_results.json")

if __name__ == "__main__":
    main()