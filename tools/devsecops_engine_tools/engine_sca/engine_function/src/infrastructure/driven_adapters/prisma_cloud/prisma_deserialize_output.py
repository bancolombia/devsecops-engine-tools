from devsecops_engine_tools.engine_sca.engine_function.src.domain.model.gateways.deserealizator_gateway import (
    DeseralizatorGateway,
)
from devsecops_engine_tools.engine_core.src.domain.model.finding import (
    Finding,
    Category,
)
from datetime import datetime
from dataclasses import dataclass

@dataclass
class PrismaDeserealizator(DeseralizatorGateway):
    def get_list_findings(self, function_scanned: dict) -> "list[Finding]":
        if function_scanned is None:
            return function_scanned

        list_open_vulnerabilities = []
        SEVERITY_MAP = {
            "unimportant": "low",
            "unassigned": "low",
            "negligible": "low",
            "not yet assigned": "low",
            "low": "low",
            "medium": "medium",
            "moderate": "medium",
            "high": "high",
            "important": "high",
            "critical": "critical",
        }
        vuls_data = function_scanned["results"][0]["vulnerabilities"]

        if len(vuls_data) > 0:
            vulnerabilities = [
                Finding(
                    id=vul.get("id", ""),
                    cvss=float(vul.get("cvss", 0.0)),
                    where=vul.get("packageName", "")
                    + ":"
                    + vul.get("packageVersion", ""),
                    description=vul.get("description", "")[:150],
                    severity=SEVERITY_MAP.get(vul.get("severity", ""), ""),
                    identification_date=vul.get("discoveredDate", ""),
                    published_date_cve=vul.get("publishedDate", "").replace(
                        "Z", "+00:00"
                    ),
                    module="engine_function",
                    category=Category.VULNERABILITY,
                    requirements=vul.get("status", ""),
                    tool="PrismaCloud",
                )
                for vul in vuls_data
            ]
        else:
            vulnerabilities = []

        # Add the Vulnerability instances to the list
        list_open_vulnerabilities.extend(vulnerabilities)

        return list_open_vulnerabilities
