import json
import os

def extract_context_from_results(file_path, category_filter=None, module=None):
    context_list = []

    try:
        if not os.path.exists(file_path):
            print(f"Warning: File not found: {file_path}")
            return context_list

        with open(file_path, "r") as results_file:
            results_data = json.load(results_file)

            if module == "engine_iac" and "results" in results_data:
                failed_checks = results_data.get("results", {}).get("failed_checks", [])
                for check in failed_checks:
                    file_line_range = check.get("file_line_range", ["N/A", "N/A"])
                    start_line = file_line_range[0] if len(file_line_range) > 0 else "N/A"
                    end_line = file_line_range[1] if len(file_line_range) > 1 else "N/A"
                    line_number = start_line if start_line == end_line else f"{start_line}-{end_line}"

                    repo_file_path = check.get("file_abs_path", "N/A")
                    resource = check.get("resource", "N/A")

                    formatted_file_path = f"{os.path.basename(repo_file_path)}/{repo_file_path}: {resource} (line {line_number})"

                    context_list.append({
                        "severity": check.get("severity"),
                        "check_id": check.get("check_id"),
                        "check_name": check.get("check_name"),
                        "file_abs_path": formatted_file_path,
                        "line_number": line_number,
                        "module": module,
                    })

            elif module == "engine_container" and "Results" in results_data:
                for result in results_data["Results"]:
                    vulnerabilities = result.get("Vulnerabilities", [])
                    for vuln in vulnerabilities:
                        if category_filter and vuln.get("Severity") != category_filter:
                            continue

                        repo_file_path = result.get("Target", "N/A")  
                        context_list.append({
                            "severity": vuln.get("Severity"),
                            "vulnerability_id": vuln.get("VulnerabilityID"),
                            "tag": module,
                            "repo_file_path": repo_file_path,
                        })

    except FileNotFoundError:
        print(f"Results file not found: {file_path}")
    except json.JSONDecodeError:
        print(f"Error decoding JSON from: {file_path}")

    print(f"\nContext extracted from {module} scan:")
    for context in context_list:
        if module == "engine_iac":
            print(
                f"Severity: {context['severity']}\n"
                f"Check ID: {context['check_id']}\n"
                f"Check Name: {context['check_name']}\n"
                f"Repo File Path: {context['file_abs_path']}\n"
                f"Tag: {context['module']}\n"
            )
        elif module == "engine_container":
            print(
                f"Severity: {context['severity']}\n"
                f"Vulnerability ID: {context['vulnerability_id']}\n"
                f"Repo File Path: {context['repo_file_path']}\n"
                f"Tag: {context['tag']}\n"
            )

    return context_list