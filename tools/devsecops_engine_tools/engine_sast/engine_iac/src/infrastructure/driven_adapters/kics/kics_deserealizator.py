from devsecops_engine_tools.engine_core.src.domain.model.finding import (
    Category,
    Finding,
)
from datetime import datetime
from dataclasses import dataclass


@dataclass
class KicsDeserealizator:
    def get_list_finding(self, results_scan_list: list) -> "list[Finding]":
        list_open_findings = []

        for result in results_scan_list:
            finding_open = Finding(
                id="IAC_SCANNING",
                cvss=None,
                where=result.get("file_name"),
                description=result.get("description"),
                severity=result.get("severity").lower(),
                identification_date=datetime.now().strftime("%d%m%Y"),
                published_date_cve=None,
                module="engine_iac",
                category=Category.VULNERABILITY,
                requirements=None,
                tool="Kics"
            )
            list_open_findings.append(finding_open)

        return list_open_findings
