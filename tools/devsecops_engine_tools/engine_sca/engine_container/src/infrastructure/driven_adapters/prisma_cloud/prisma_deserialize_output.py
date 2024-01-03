from devsecops_engine_tools.engine_sca.engine_container.src.domain.model.gateways.deserealizator_gateway import DeseralizatorGateway
from devsecops_engine_tools.engine_core.src.domain.model.finding import Finding
from datetime import datetime
from dataclasses import dataclass
import json

@dataclass
class PrismaDeserealizator(DeseralizatorGateway):
    
    def get_list_vulnerability(self, images_scanned: list) -> "list[Finding]":
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
        for image in images_scanned:
            with open(image, "rb") as file:
                image_object = file.read()
                      
                json_data = json.loads(image_object)

                vulnerabilities_data = json_data["results"][0]["vulnerabilities"]

                # Create a list of Vulnerability instances from the JSON data
                vulnerabilities = [
                    Vulnerability(
                        id=vul.get("id", ""),
                        cvss=float(vul.get("cvss", 0.0)),
                        where_vulnerability=vul.get("link", ""),
                        description=vul.get("description", "")[:150],
                        severity=SEVERITY_MAP.get(vul.get("severity", ""), ""),
                        identification_date=datetime.strptime(vul.get("discoveredDate", ""), "%Y-%m-%dT%H:%M:%S%z"),
                        type_vulnerability="SCA",
                        requirements=vul.get("status", ""),
                        tool="PrismaCloud",
                        is_excluded=False,
                    )
                    for vul in vulnerabilities_data
                ]

                # Add the Vulnerability instances to the list
                list_open_vulnerabilities.extend(vulnerabilities)
       
        return list_open_vulnerabilities

