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
        cls, results_scan_list: list, rules
    ) -> "list[Finding]":
        list_open_findings = []

        for result in results_scan_list:
            if "failed_checks" in str(result):
                for scan in result["results"]["failed_checks"]:
                    finding_open = Finding(
                        id=scan.get("check_id"),
                        cvss=None,
                        where = scan.get("repo_file_path") + ": " + str(scan.get("resource")),
                        description=rules[scan.get("check_id")].get("checkID", scan.get("check_name")),
                        severity=rules[scan.get("check_id")].get("severity").lower(),
                        identification_date=datetime.now().strftime("%d%m%Y"),
                        published_date_cve=None,
                        module="engine_iac",
                        category=Category(rules[scan.get("check_id")].get("category").lower()),
                        requirements=scan.get("guideline"),
                        tool="Checkov"
                    )
                    list_open_findings.append(finding_open)

        return list_open_findings