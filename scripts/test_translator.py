import os
import json
import subprocess
import yaml
from collections import defaultdict

def find_diverse_rules(sigma_dir="sigma", max_rules_per_category=3):
    """
    Find a diverse set of Sigma rules to test the translator.
    
    Args:
        sigma_dir: The base directory containing Sigma rules
        max_rules_per_category: Maximum number of rules to select per category
        
    Returns:
        A list of rule paths to test
    """
    # Load the analysis results if available
    if os.path.exists("sigma_analysis_results.json"):
        with open("sigma_analysis_results.json", 'r', encoding='utf-8') as f:
            analysis = json.load(f)
        
        # Get the top categories
        top_categories = sorted(analysis["logsource_categories"].items(), 
                               key=lambda x: x[1], reverse=True)[:10]
        
        # Get the top condition patterns
        top_conditions = sorted(analysis["condition_patterns"].items(),
                               key=lambda x: x[1], reverse=True)[:10]
        
        # Use the sample rules from the analysis
        test_rules = []
        
        # Add rules from different categories
        for category, _ in top_categories:
            if category in analysis["sample_rules_by_category"]:
                samples = analysis["sample_rules_by_category"][category]
                for sample in samples[:max_rules_per_category]:
                    test_rules.append(sample["path"])
        
        # Add rules with complex conditions
        for condition in analysis["complex_conditions"][:10]:
            if condition["path"] not in test_rules:
                test_rules.append(condition["path"])
                
        return test_rules
    
    # If analysis results are not available, find rules manually
    test_rules = []
    category_count = defaultdict(int)
    
    # Walk through all directories in the sigma_dir
    for root, dirs, files in os.walk(sigma_dir):
        for file in files:
            if file.endswith(".yml"):
                rule_path = os.path.join(root, file)
                try:
                    with open(rule_path, 'r', encoding='utf-8') as f:
                        rule = yaml.safe_load(f)
                    
                    if "logsource" in rule and "category" in rule["logsource"]:
                        category = rule["logsource"]["category"]
                        
                        # If we haven't reached the max for this category, add the rule
                        if category_count[category] < max_rules_per_category:
                            test_rules.append(rule_path)
                            category_count[category] += 1
                
                except Exception as e:
                    print(f"Error processing {rule_path}: {e}")
    
    return test_rules

def test_translator(rule_paths):
    """
    Test the translator with the given rule paths.
    
    Args:
        rule_paths: A list of rule paths to test
        
    Returns:
        A dictionary with the test results
    """
    results = {
        "success": [],
        "failure": []
    }
    
    for rule_path in rule_paths:
        print(f"Testing rule: {rule_path}")
        try:
            # Run the translator on the rule
            result = subprocess.run(
                ["python", "translate_sigma_rule.py", rule_path],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                print("  Success!")
                results["success"].append({
                    "path": rule_path,
                    "output": result.stdout
                })
            else:
                print(f"  Failed: {result.stderr}")
                results["failure"].append({
                    "path": rule_path,
                    "error": result.stderr
                })
        
        except Exception as e:
            print(f"  Error: {e}")
            results["failure"].append({
                "path": rule_path,
                "error": str(e)
            })
    
    return results

def main():
    # Find diverse rules to test
    print("Finding diverse rules to test...")
    test_rules = find_diverse_rules()
    
    print(f"Found {len(test_rules)} rules to test.")
    
    # Test the translator
    print("\nTesting translator...")
    results = test_translator(test_rules)
    
    # Print summary
    print("\nTest Summary:")
    print(f"  Success: {len(results['success'])}")
    print(f"  Failure: {len(results['failure'])}")
    
    if results["failure"]:
        print("\nFailed rules:")
        for failure in results["failure"]:
            print(f"  {failure['path']}")
            print(f"    Error: {failure['error']}")
    
    # Save results to a file
    with open("translator_test_results.json", 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)
    
    print("\nDetailed results saved to translator_test_results.json")

if __name__ == "__main__":
    main()