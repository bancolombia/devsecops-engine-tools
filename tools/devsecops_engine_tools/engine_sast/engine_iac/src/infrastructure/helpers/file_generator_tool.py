import json
import os
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


def generate_file_from_tool(tool, result_list, rules_doc):
    if tool == "CHECKOV":
        try:
            if len(result_list) > 0:
                all_failed_checks = []
                summary_passed = 0
                summary_failed = 0
                summary_skipped = 0
                summary_parsing_errors = 0
                summary_resource_count = 0
                checkov_version = None
                for result in result_list:
                    failed_checks = result.get("results", {}).get("failed_checks", [])
                    all_failed_checks.extend(
                        map(lambda x: update_fields(x, rules_doc), failed_checks)
                    )
                    summary_passed += result.get("summary", {}).get("passed", 0)
                    summary_failed += result.get("summary", {}).get("failed", 0)
                    summary_skipped += result.get("summary", {}).get("skipped", 0)
                    summary_parsing_errors += result.get("summary", {}).get(
                        "parsing_errors", 0
                    )
                    summary_resource_count += result.get("summary", {}).get(
                        "resource_count", 0
                    )
                    checkov_version = result.get("summary", {}).get(
                        "checkov_version", None
                    )

                file_name = "results.json"
                results_data = {
                    "check_type": "Dockerfile, Kubernetes and CloudFormation",
                    "results": {
                        "failed_checks": all_failed_checks,
                    },
                    "summary": {
                        "passed": summary_passed,
                        "failed": summary_failed,
                        "skipped": summary_skipped,
                        "parsing_errors": summary_parsing_errors,
                        "resource_count": summary_resource_count,
                        "checkov_version": checkov_version,
                    },
                }

                with open(file_name, "w") as json_file:
                    json.dump(results_data, json_file, indent=4)

                absolute_path = os.path.abspath(file_name)
                return absolute_path
        except Exception as ex:
            logger.error(f"Error during handling checkov json integrator {ex}")


def generate_file_from_kubescape(result_list):
    try:
        if result_list:
            all_failed_checks = []
            summary_passed = 0
            summary_failed = 0
            kubescape_version = result_list.get("metadata", {}).get("scanMetadata", {}).get("kubescapeVersion")

            frameworks = result_list.get("summaryDetails", {}).get("frameworks", [])

            for framework in frameworks:
                controls = framework.get("controls", {})
                for control_id, control_data in controls.items():
                    if control_data['status'] == 'failed':
                        all_failed_checks.append({control_id: control_data})
                        summary_failed += 1

                    if control_data['status'] == 'passed':
                        summary_passed += 1

            file_name = "results_scan.json"
            results_data = {
                "check_type": "Dockerfile, Kubernetes and CloudFormation",
                "results": {
                    "failed_checks": all_failed_checks,
                },
                "summary": {
                    "passed": summary_passed,
                    "failed": summary_failed,
                    "kubescape_version": kubescape_version,
                },
            }

            with open(file_name, "w") as json_file:
                json.dump(results_data, json_file, indent=4)

            absolute_path = os.path.abspath(file_name)
            return absolute_path

    except Exception as ex:
        logger.error(f"Error during handling kubescape json integrator {ex}")


def generate_file_from_kics(result_list):
    try:
        if result_list:

            queries = result_list.get("queries", [])

            file_name = "results_scan.json"
            results_data = {
                "check_type": "Dockerfile, Kubernetes and CloudFormation",
                "results": {
                    "failed_checks": queries,
                },
                "summary": {
                    "files_scanned": result_list.get("files_scanned", 0),
                    "lines_scanned": result_list.get("lines_scanned", 0),
                    "files_parsed": result_list.get("files_parsed", 0),
                    "lines_parsed": result_list.get("lines_parsed", 0),
                    "queries_total": result_list.get("queries_total", 0)
                },
            }

            with open(file_name, "w") as json_file:
                json.dump(results_data, json_file, indent=4)

            absolute_path = os.path.abspath(file_name)
            return absolute_path

    except Exception as ex:
        logger.error(f"Error during handling kubescape json integrator {ex}")


def update_fields(check_result, rules_doc):
    rule_info = rules_doc.get(check_result.get("check_id"), {})

    check_result["severity"] = rule_info["severity"].lower()
    if "customID" in rule_info:
        check_result["custom_vuln_id"] = rule_info["customID"]
    if "guideline" in rule_info:
        check_result["guideline"] = rule_info["guideline"]
    if "category" in rule_info:
        check_result["bc_category"] = rule_info["category"]

    return check_result
