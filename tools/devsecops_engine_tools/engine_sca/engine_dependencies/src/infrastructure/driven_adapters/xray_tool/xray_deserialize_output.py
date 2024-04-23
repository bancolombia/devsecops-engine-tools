from devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.model.gateways.deserializator_gateway import (
    DeserializatorGateway,
)
from devsecops_engine_tools.engine_core.src.domain.model.finding import (
    Finding,
    Category,
)
from dataclasses import dataclass
import json
from datetime import datetime


@dataclass
class XrayDeserializator(DeserializatorGateway):
    def set_list_finding(self, vul):
        vulnerabilities = [
            Finding(
                id=vul.get("issue_id", ""),
                cvss=(
                    vul["cves"][0].get("cvss_v3_score")
                    if vul.get("cves", 0) and vul["cves"][0].get("cvss_v3_score", 0)
                    else ""
                )
                + (
                    vul["cves"][0].get("cvss_v2_score")
                    if vul.get("cves", 0)
                    and not (vul["cves"][0].get("cvss_v3_score", 0))
                    and vul["cves"][0].get("cvss_v2_score", 0)
                    else ""
                ),
                where=(component),
                description=(
                    vul["cves"][0].get("cve", "") if vul.get("cves", 0) else ""
                ),
                severity=vul.get("severity", "").lower(),
                identification_date=datetime.now().strftime("%d-%m-%Y %H:%M:%S"),
                published_date_cve=None,
                module="engine_dependencies",
                category=Category.VULNERABILITY,
                requirements=(
                    "".join(vul["components"][component].get("fixed_versions", [""]))
                ),
                tool="XRAY",
            )
            for component in vul.get("components", [])
        ]
        return vulnerabilities

    def get_list_findings(self, dependencies_scanned_file) -> "list[Finding]":
        list_open_vulnerabilities = []
        with open(dependencies_scanned_file, "rb") as file:
            json_data = json.loads(file.read())
            if json_data:
                for data in json_data:
                    for vul in data.get("vulnerabilities", []):
                        list_open_vulnerabilities.extend(self.set_list_finding(vul))
        return list_open_vulnerabilities
