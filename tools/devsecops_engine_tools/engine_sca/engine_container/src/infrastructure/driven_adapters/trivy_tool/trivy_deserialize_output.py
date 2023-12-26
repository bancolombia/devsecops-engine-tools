from devsecops_engine_tools.engine_sca.engine_container.src.domain.model.gateways.deserealizator_gateway import (
    DeseralizatorGateway
    )
from devsecops_engine_tools.engine_core.src.domain.model.vulnerability import (
    Vulnerability
    )
from datetime import datetime
from dataclasses import dataclass
import json

@dataclass
class TrivyDeserializator(DeseralizatorGateway):
    
    def get_list_vulnerability(self, images_scanned: list) -> "list[Vulnerability]":
        list_open_vulnerabilities = []
        for image in images_scanned:
            with open(image, "rb") as file:
                image_object = file.read()
                      
                json_data = json.loads(image_object)

                if 'Results' in json_data:
                    vulnerabilities_data = json_data["Results"][0]["Vulnerabilities"]
                    vulnerabilities = []
                    for vul in vulnerabilities_data:
                        if 'CVSS' in vul:
                            vulnerabilities.append(
                                Vulnerability(
                                id=vul.get("VulnerabilityID",""),
                                cvss=next((v["V3Score"] for v in vul["CVSS"].values() if "V3Score" in v), None),
                                where_vulnerability=vul.get("PkgName", ""),
                                description=vul.get("Description", ""),
                                severity=vul.get("Severity", "").lower(),
                                identification_date=vul.get("PublishedDate", ""),
                                type_vulnerability="SCA",
                                requirements=next((v["V3Vector"] for v in vul["CVSS"].values() if "V3Vector" in v), None),
                                tool="Trivy",
                                is_excluded=False,
                                )
                            )
                        else:
                            vulnerabilities.append(
                                Vulnerability(
                                id=vul.get("VulnerabilityID",""),
                                cvss="",
                                where_vulnerability=vul.get("PkgName", ""),
                                description=vul.get("Description", ""),
                                severity="low",
                                identification_date=vul.get("PublishedDate", ""),
                                type_vulnerability="SCA",
                                requirements="",
                                tool="Trivy",
                                is_excluded=False,
                                )
                            )
                    list_open_vulnerabilities.extend(vulnerabilities)
        print("hola mundo")
        return list_open_vulnerabilities

