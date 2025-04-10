import json
import json
from datetime import datetime

def generate_file_from_tool(tool_name, result_scans, config_tool):
    if tool_name == "JWT":
        sarif_report = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": tool_name,
                            "version": "1.0.0",
                            "rules": [
                                {
                                    "id": rule_id,
                                    "shortDescription": {"text": rule["description"]},
                                    "helpUri": rule.get("helpUri", ""),
                                    "properties": {
                                        "severity": rule.get("severity", "medium"),
                                        "cvss": rule.get("cvss", 0)
                                    }
                                }
                                for rule_id, rule in config_tool.get("RULES", {}).items()
                            ]
                        }
                    },
                    "results": [
                        {
                            "ruleId": result["check_id"],
                            "message": {"text": result["description"]},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {
                                            "uri": result["matched-at"]
                                        }
                                    }
                                }
                            ],
                            "properties": {
                                "severity": result["severity"],
                                "cvss": result["cvss"],
                                "remediation": result.get("remediation", "No remediation provided")
                            }
                        }
                        for result in result_scans
                    ]
                }
            ]
        }

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        sarif_file_path = f"{tool_name}_report_{timestamp}.sarif"
        
        with open(sarif_file_path, "w", encoding="utf-8") as sarif_file:
            json.dump(sarif_report, sarif_file, indent=4)

        return sarif_file_path