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
                        description = rules[check_id].get(
                            "checkID", scan.get("check_name")
                        )
                        severity = rules[check_id].get("severity").lower()
                        category = rules[check_id].get("category").lower()

                    finding_open = Finding(
                        id=check_id,
                        cvss=None,
                        where=scan.get("repo_file_path")
                        + ": "
                        + str(scan.get("resource")),
                        description=description,
                        severity=severity,
                        identification_date=datetime.now().strftime("%d%m%Y"),
                        published_date_cve=None,
                        module="engine_iac",
                        category=Category(category),
                        requirements=scan.get("guideline"),
                        tool="Checkov",
                    )
                    list_open_findings.append(finding_open)

        return list_open_findings
