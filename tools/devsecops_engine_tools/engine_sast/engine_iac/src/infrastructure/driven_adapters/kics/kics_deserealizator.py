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
                id=result.get("id"),
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

    def get_findings(self, data):
        filtered_results = []
        for query in data.get("queries", []):
            severity = query.get("severity", "").upper()
            if severity in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
                description = query.get("query_name", "")
                query_id = query.get("query_id", "")
                for file in query.get("files", []):
                    file_name = file.get("file_name", "")
                    filtered_results.append({
                        "severity": severity,
                        "description": description,
                        "file_name": file_name,
                        "id": query_id
                    })
        return filtered_results

    def calculate_total_vulnerabilities(self, data):
        severity_counters = data.get("severity_counters", {})

        critical = severity_counters.get("CRITICAL", 0)
        high = severity_counters.get("HIGH", 0)
        medium = severity_counters.get("MEDIUM", 0)
        low = severity_counters.get("LOW", 0)

        return critical + high + medium + low
