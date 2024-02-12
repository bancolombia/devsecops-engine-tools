import json
import os
from devsecops_engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()

def generate_file_from_tool(tool, result_list, rules_doc):
    if tool == "CHECKOV":
        try:
            result_one: dict = {}
            result_two: dict = {}
            result_three: dict = {}
            if len(result_list) > 1:
                result_one = result_list[0]
                result_two = result_list[1]
                result_three = result_list[2]
            file_name = "results.json"
            results_data = {
                "check_type": "Dockerfile and Kubernetes",
                "results": {
                    "failed_checks": list(
                        map(
                            lambda x: update_field(
                                x,
                                "severity",
                                rules_doc[x.get("check_id")].get("severity").lower(),
                            ),
                            result_one.get("results", {}).get("failed_checks", []),
                        )
                    )
                    + list(
                        map(
                            lambda x: update_field(
                                x,
                                "severity",
                                rules_doc[x.get("check_id")].get("severity").lower(),
                            ),
                            result_two.get("results", {}).get("failed_checks", []),
                        )
                    )
                    + list(
                        map(
                            lambda x:
                            update_field(
                            {**x, "custom_vuln_id": rules_doc[x.get("check_id")].get("customID")},
                            "severity",
                            rules_doc[x.get("check_id")].get("severity").lower(),
                            )
                            ,
                            result_three.get("results", {}).get("failed_checks", []),
                        )
                    )
                },
                "summary": {
                    "passed": result_one.get("summary", {}).get("passed", 0)
                    + result_two.get("summary", {}).get("passed", 0),
                    "failed": result_one.get("summary", {}).get("failed", 0)
                    + result_two.get("summary", {}).get("failed", 0),
                    "skipped": result_one.get("summary", {}).get("skipped", 0)
                    + result_two.get("summary", {}).get("skipped", 0),
                    "parsing_errors": result_one.get("summary", {}).get(
                        "parsing_errors", 0
                    )
                    + result_one.get("summary", {}).get("parsing_errors", 0),
                    "resource_count": result_one.get("summary", {}).get(
                        "resource_count", 0
                    )
                    + result_two.get("summary", {}).get("resource_count", 0),
                    "checkov_version": result_one.get("summary", {}).get(
                        "checkov_version", None
                    ),
                },
            }

            with open(file_name, "w") as json_file:
                json.dump(results_data, json_file, indent=4)

            absolute_path = os.path.abspath(file_name)
            return absolute_path
        except Exception as ex:
            logger.error(f"Error during handling checkov json integrator {ex}")


def update_field(elem, field, new_value):
    return {**elem, field: new_value}
