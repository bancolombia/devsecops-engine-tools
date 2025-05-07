import json
from devsecops_engine_tools.engine_core.src.domain.model.context_iac import ContextIac
from devsecops_engine_tools.engine_core.src.domain.model.finding import (
    Category,
    Finding,
)
from datetime import datetime
from dataclasses import dataclass


@dataclass
class CheckovDeserealizator:
    @classmethod
    def get_list_finding(
        cls, results_scan_list: list, rules, default_severity, default_category
    ) -> "list[Finding]":

        list_open_findings = []
        for result in results_scan_list:
            if "failed_checks" in str(result):
                for scan in result["results"]["failed_checks"]:
                    check_id = scan.get("check_id")
                    if not rules.get(check_id):
                        description = scan.get("check_name")
                        severity = default_severity.lower()
                        category = default_category.lower()
                    else:
                        description = rules[check_id].get("checkID", scan.get("check_name"))
                        severity = rules[check_id].get("severity").lower()
                        category = rules[check_id].get("category").lower()

                    finding_open = Finding(
                        id=check_id,
                        cvss=None,
                        where=scan.get("repo_file_path") + ": " + str(scan.get("resource")),
                        description=description,
                        severity=severity,
                        identification_date=datetime.now().strftime("%d%m%Y"),
                        published_date_cve=None,
                        module="engine_iac",
                        category=Category(category),
                        requirements=scan.get("guideline"),
                        tool="Checkov"
                    )
                    list_open_findings.append(finding_open)

        return list_open_findings
    
    @classmethod
    def get_iac_context_from_results(
        cls, context_results_scan_list: list, rules, default_severity
    ) -> None:

        context_iac_list = []
        for result in context_results_scan_list:
            if "failed_checks" in result.get("results", {}):
                failed_checks = result["results"]["failed_checks"]
                for check in failed_checks:
                    check_id = check.get("check_id")
                    rule_info = rules.get(check_id, {})

                    severity = rule_info.get("severity", default_severity).lower()
                    file_line_range = check.get("file_line_range", ["N/A", "N/A"])
                    start_line = file_line_range[0] if len(file_line_range) > 0 else "N/A"
                    end_line = file_line_range[1] if len(file_line_range) > 1 else "N/A"
                    line_range_str = f"{start_line}-{end_line}" if start_line != end_line else str(start_line)

                    context_iac = ContextIac(
                        id=check.get("check_id", "N/A"),
                        custom_vuln_id=check.get("check_id", "N/A"),
                        check_name=check.get("check_name", "N/A"),
                        check_class=check.get("check_class", "N/A"),
                        severity=severity,
                        where=f"{check.get('repo_file_path', 'N/A')}: {check.get('resource', 'N/A')} (line {line_range_str})",
                        resource=check.get("resource", "N/A"),
                        description=check.get("check_name", "N/A"),
                        module="engine_iac",
                        tool="Checkov"
                    )

                    context_iac_list.append(context_iac)
                    
        print("===== BEGIN CONTEXT OUTPUT =====")
        print(json.dumps({"iac_context": [obj.__dict__ for obj in context_iac_list] }, indent=4))
        print("===== END CONTEXT OUTPUT =====")