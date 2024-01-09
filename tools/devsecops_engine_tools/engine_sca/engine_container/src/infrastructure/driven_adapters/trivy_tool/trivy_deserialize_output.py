from devsecops_engine_tools.engine_sca.engine_container.src.domain.model.gateways.deserealizator_gateway import (
    DeseralizatorGateway
    )
from devsecops_engine_tools.engine_core.src.domain.model.finding import (
    Finding,
    Category
    )
# from datetime import datetime
from dataclasses import dataclass
import json

@dataclass
class TrivyDeserializator(DeseralizatorGateway):

    def get_list_vulnerability(self, images_scanned: list) -> "list[Finding]":
        list_open_vulnerabilities = []
        for image in images_scanned:
            with open(image, "rb") as file:
                image_object = file.read()
                json_data = json.loads(image_object)
                if 'Vulnerabilities' in json_data['Results'][0]:
                    vulnerabilities_data = json_data["Results"][0]["Vulnerabilities"]
                    vulnerabilities = []
                    for vul in vulnerabilities_data:
                        if 'CVSS' in vul:
                            vulnerabilities.append(
                                Finding(
                                id=vul.get("VulnerabilityID",""),
                                cvss=next((v["V3Score"] for v in vul["CVSS"].values() if "V3Score" in v), None),
                                where=vul.get("PkgName", "")+" "+vul.get("InstalledVersion", ""),
                                description=vul.get("Description", "").replace("\n",""),
                                severity=vul.get("Severity", "").lower(),
                                identification_date=vul.get("PublishedDate", ""),
                                module="CONTAINER",
                                category=Category.VULNERABILITY,
                                requirements=vul.get("FixedVersion") if vul.get("FixedVersion") else vul.get("Status", ""),
                                tool="Trivy",
                                )
                            )
                    list_open_vulnerabilities.extend(vulnerabilities)
        return list_open_vulnerabilities