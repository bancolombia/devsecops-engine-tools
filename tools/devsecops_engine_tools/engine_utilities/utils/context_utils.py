import json
import os

def extract_context_from_results(file_path, category_filter=None,module=None):
    """
    Extracts context from a results file (IaC or container scan).

    :param file_path: Path to the results file (e.g., results.json or container_scan_result.json).
    :param category_filter: Optional filter for a specific category (e.g., "VULNERABILITY", "COMPLIANCE").
    :return: List of extracted context dictionaries.
    """
    
    context_list = []
    results_file_path = "results.json"  # Ensure this path is correct
    try:
        with open(results_file_path, "r") as results_file:
            results_data = json.load(results_file)
            failed_checks = results_data.get("results", {}).get("failed_checks", [])
            for check in failed_checks:
                line_number = check.get("line_number", "N/A")  # Default to "N/A" if not present
                repo_file_path = check.get("file_abs_path", "N/A")
                context_list.append({
                    "severity": check.get("severity"),
                    "check_id": check.get("check_id"),
                    "check_name": check.get("check_name"),
                    "file_abs_path": check.get("file_abs_path"),
                    "line_number": line_number,
                    "module": module,
                })
    except FileNotFoundError:
        print(f"Results file not found: {results_file_path}")
    except json.JSONDecodeError:
        print(f"Error decoding JSON from: {results_file_path}")

    # Log the context after execution
    print("\nContext extracted from IaC scan:")
    for context in context_list:
        print(
            f"Severity: {context['severity']}\n"
            f"Check ID: {context['check_id']}\n"
            f"Check Name: {context['check_name']}\n"
            f"Repo File Path: {context['file_abs_path']} (line {context['line_number']})\n" 
            f"Module: {context['module']}\n"
        )

    return context_list