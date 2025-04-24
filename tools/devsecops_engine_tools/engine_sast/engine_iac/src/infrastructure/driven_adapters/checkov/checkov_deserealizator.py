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
        cls, results_scan_list: list
        ) -> list[dict]:
        
        context_list = []
        for result in results_scan_list:
            if "failed_checks" in result.get("results", {}):
                failed_checks = result["results"]["failed_checks"]
                for check in failed_checks:
                    file_line_range = check.get("file_line_range", ["N/A", "N/A"])
                    start_line = file_line_range[0] if len(file_line_range) > 0 else "N/A"
                    end_line = file_line_range[1] if len(file_line_range) > 1 else "N/A"
                    line_number = start_line if start_line == end_line else f"{start_line}-{end_line}"

                    repo_file_path = check.get("repo_file_path", "N/A")
                    resource = check.get("resource", "N/A")

                    formatted_file_path = f"{repo_file_path}: {resource} (line {line_number})"

                    context_list.append({
                        "severity": check.get("severity"),
                        "check_id": check.get("check_id"),
                        "check_name": check.get("check_name"),
                        "file_abs_path": formatted_file_path,
                        "line_number": line_number,
                        "module": "engine_iac",
                    })

        print(f"\n\nContext extracted from engine_iac scan:")
        for context in context_list:
            print(
                f"Severity: {context['severity']}\n"
                f"Check ID: {context['check_id']}\n"
                f"Check Name: {context['check_name']}\n"
                f"Repo File Path: {context['file_abs_path']}\n"
                f"Tag: {context['module']}\n"
            )

        return context_list