from devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.model.gateways.deserializator_gateway import (
    DeserializatorGateway,
)
from devsecops_engine_tools.engine_core.src.domain.model.finding import (
    Finding,
    Category,
)
from dataclasses import dataclass
import json

@dataclass
class XrayDeserializator(DeserializatorGateway):
    def get_list_findings(self, dependencies_scanned_file) -> "list[Finding]":
        list_open_vulnerabilities = []
        with open(dependencies_scanned_file, "rb") as file:
            json_data = json.loads(file.read())
            vulnerabilities = []
            vulnerabilities_data = json_data['vulnerabilities']
            if vulnerabilities_data is not None:
                vulnerabilities = [
                    Finding(
                        id=vul["issueId"] if vul.get("issueId", 1) else "",
                        cvss=vul["cves"][0]["id"] if vul.get("cves", 1) else "",
                        where=(vul["impactedPackageName"] if vul.get("impactedPackageName", 1) else "")
                        + ":"
                        + (vul["impactedPackageVersion"] if vul.get("impactedPackageVersion", 1) else ""),
                        description=vul["summary"].replace("\n", "") if vul.get("summary", 1) else "",
                        severity=vul["severity"].lower() if vul.get("severity", 1) else "",
                        identification_date="",
                        module="engine_dependencies",
                        category=Category.VULNERABILITY,
                        requirements="\n".join(map(str, vul["fixedVersions"])) if vul.get("fixedVersions", 1) else "",
                        tool="Xray",
                    )
                    for vul in vulnerabilities_data
                ]
            list_open_vulnerabilities.extend(vulnerabilities)
        return list_open_vulnerabilities