from dataclasses import (
    dataclass,
)
from datetime import (
    datetime,
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
                    cvss=scan["info"].get("classification", {}).get("cvss-score", ""),
                    where=scan.get("matched-at"),
                    description=scan["info"].get("description"),
                    severity=scan["info"].get("severity").lower() if scan["info"].get("severity").lower() != "info" else "low",
                    identification_date=datetime.now().strftime("%d%m%Y"),
                    module="engine_dast",
                    category=Category("vulnerability"),
                    requirements=scan["info"].get("remediation"),
                    tool="Nuclei",
                    published_date_cve=None
                )
                list_open_findings.append(finding_open)

        return list_open_findings

