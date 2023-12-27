from devsecops_engine_tools.engine_core.src.domain.model.vulnerability import (
    Vulnerability,
)
from datetime import datetime
from dataclasses import dataclass


@dataclass
class CheckovDeserealizator:
    def get_list_vulnerability(
        self, results_scan_list: list, rules
    ) -> "list[Vulnerability]":
        list_open_vulnerabilities = []

        for result in results_scan_list:
            if "failed_checks" in str(result):
                for scan in result["results"]["failed_checks"]:
                    vulnerability_open = Vulnerability(
                        id=scan.get("check_id"),
                        cvss=None,
                        where_vulnerability=scan.get("repo_file_path"),
                        description=scan.get("check_name"),
                        severity=rules[scan.get("check_id")].get("severity").lower(),
                        identification_date=datetime.now().strftime("%d%m%Y"),
                        type_vulnerability="IaC",
                        requirements=scan.get("guideline"),
                        tool="Checkov",
                        is_excluded=False,
                    )
                    list_open_vulnerabilities.append(vulnerability_open)

        return list_open_vulnerabilities
