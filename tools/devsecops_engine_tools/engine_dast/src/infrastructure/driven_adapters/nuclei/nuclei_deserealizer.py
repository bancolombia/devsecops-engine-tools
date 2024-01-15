from dataclasses import (
    dataclass,
)
from datetime import (
    datetime,
)
from typing import (
    Any,
)
from devsecops_engine_tools.engine_core.src.domain.model.finding import (
    Category,
    Finding,
)


@dataclass
class NucleiDesealizator:
    @classmethod
    def get_list_finding(
        cls,
        results_scan_list: "list[dict]",
    ) -> "list[Finding]":
        list_open_findings = []

        if len(results_scan_list) > 0:
            for scan in results_scan_list:
                finding_open = Finding(
                    id=scan.get("template-id"),
                    cvss=scan["info"]["classification"].get("cvss-score"),
                    where=scan.get("matched-at"),
                    description=scan["info"].get("description"),
                    severity=scan["info"].get("severity").lower(),
                    identification_date=datetime.now().strftime("%d%m%Y"),
                    module="engine_dast",
                    category=Category(scan["info"].get("category")),
                    requirements=scan["info"].get("remediation"),
                    tool="Nuclei",
                )
                list_open_findings.append(finding_open)

        return list_open_findings


"""
    def print_table(
        self, vulnerabilities_without_exclusions_list: "list[Vulnerability]" = []
    ):
        if isinstance(vulnerabilities_without_exclusions_list, list):
            if len(vulnerabilities_without_exclusions_list) > 0:
                vulnerability_table = PrettyTable(
                    ["Severity", "ID", "Description", "Where"]
                )

                for vulnerability in vulnerabilities_without_exclusions_list:
                    vulnerability_table.add_row(
                        [
                            vulnerability.severity,
                            vulnerability.id,
                            vulnerability.description,
                            vulnerability.where_vulnerability,
                        ]
                    )

                severity_order = {
                    "critical": 0,
                    "high": 1,
                    "medium": 2,
                    "low": 3,
                    "info": 4,
                }
                sorted_table = PrettyTable()
                sorted_table.field_names = vulnerability_table.field_names
                sorted_table.add_rows(
                    sorted(
                        vulnerability_table._rows,
                        key=lambda row: severity_order[row[0]],
                    )
                )

                sorted_table.align["Severity"] = "l"
                sorted_table.align["Description"] = "l"
                sorted_table.align["ID"] = "l"
                sorted_table.align["Where"] = "l"
                sorted_table.set_style(DOUBLE_BORDER)

                if len(sorted_table.rows) > 0:
                    print(sorted_table)
        else:
            print("No vulnerabiltiies found")
"""
