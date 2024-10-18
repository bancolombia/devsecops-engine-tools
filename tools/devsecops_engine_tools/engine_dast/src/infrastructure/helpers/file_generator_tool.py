import json
import os


def generate_file_from_tool(tool, result_list, rules_doc):
    if tool.lower() == "nuclei":
        try:
            result_one: dict = {}
            result_two: dict = {}
            if len(result_list) > 1:
                result_one = result_list[0]
                result_two = result_list[1]
            file_name = "results.json"
            results_data = {
                "check_type": "Api and Web Application",
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
                    "nuclei_version": result_one.get("summary", {}).get(
                        "version", None
                    ),
                },
            }

            with open(file_name, "w") as json_file:
                json.dump(results_data, json_file, indent=4)

            absolute_path = os.path.abspath(file_name)
            return absolute_path
        except KeyError as e:
            print(f"Dict KeyError in checks integration: {e}")
        except Exception as ex:
            print(f"Error during handling checkov json integrator {ex}")


def update_field(elem, field, new_value):
    return {**elem, field: new_value}