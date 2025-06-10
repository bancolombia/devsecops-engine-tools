from devsecops_engine_tools.engine_sca.engine_container.src.domain.model.context_container import ContextContainer
from devsecops_engine_tools.engine_sca.engine_container.src.domain.model.gateways.deserealizator_gateway import (
    DeseralizatorGateway,
)
from devsecops_engine_tools.engine_core.src.domain.model.finding import (
    Finding,
    Category,
)
from datetime import datetime
from dataclasses import asdict, dataclass
import json


@dataclass
class PrismaDeserealizator(DeseralizatorGateway):

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

    def get_list_findings(self, image_scanned) -> "list[Finding]":
        list_open_vulnerabilities = []
        with open(image_scanned, "rb") as file:
            image_object = file.read()

            json_data = json.loads(image_object)
            console_url = json_data.get("consoleURL", False)
            if console_url:
                print(f"Console URL: {console_url}")
            vulnerabilities_data = (
                json_data["results"][0]["vulnerabilities"]
                if "vulnerabilities" in json_data["results"][0]
                else []
            )

            # Create a list of findings instances from the JSON data
            vulnerabilities = [
                Finding(
                    id=vul.get("id", ""),
                    cvss=float(vul.get("cvss", 0.0)),
                    where=vul.get("packageName", "")
                    + ":"
                    + vul.get("packageVersion", ""),
                    description=vul.get("description", "")[:150],
                    severity=SEVERITY_MAP.get(vul.get("severity", ""), ""),
                    identification_date=datetime.strptime(
                        vul.get("discoveredDate", ""), "%Y-%m-%dT%H:%M:%S%z"
                    ),
                    published_date_cve=vul.get("publishedDate", "").replace(
                        "Z", "+00:00"
                    ),
                    module="engine_container",
                    category=Category.VULNERABILITY,
                    requirements=vul.get("status", ""),
                    tool="PrismaCloud",
                )
                for vul in vulnerabilities_data
            ]

            # Add the Vulnerability instances to the list
            list_open_vulnerabilities.extend(vulnerabilities)

        return list_open_vulnerabilities
    
    def get_container_context_from_results(self, image_scanned) -> "list[ContextContainer]":
        context_container_list = []

        with open(image_scanned, "rb") as file:
            image_object = file.read()
            json_data = json.loads(image_object)

        result = json_data.get("results", [])[0]
        vulnerabilities = result.get("vulnerabilities", [])

        for vul in vulnerabilities:
            context_container = ContextContainer(
                cve_id=vul.get("id", "unknown"),
                cwe_id=None,  # Prisma doesn’t expose CWEIDs
                vendor_id=None,  # Prisma doesn’t expose VendorIDs
                severity=self.SEVERITY_MAP.get(vul.get("severity", "unknown").lower(), "unknown"),
                vulnerability_status=vul.get("status", "unknown"),
                risk_factors=vul.get("riskFactors", []),
                target_image=result.get("name", "unknown"),
                package_name=vul.get("packageName", "unknown"),
                installed_version=vul.get("packageVersion", "unknown"),
                fixed_version=vul.get("status", "unknown"),
                cvss_score=vul.get("cvss", "unknown"),
                cvss_vector=vul.get("vector", "unknown"),
                description=vul.get("description", "").replace("\n", " "),
                os_type=result.get("distro", "unknown"),
                layer_digest=vul.get("layerTime", "unknown"),
                published_date=vul.get("publishedDate", "").replace("Z", "+00:00"),
                last_modified_date=vul.get("discoveredDate", "").replace("Z", "+00:00"),
                references=[vul.get("link")] if vul.get("link") else None,
                source_tool="PrismaCloud",
            )
            context_container_list.append(context_container)

        print("===== BEGIN CONTEXT OUTPUT =====")
        print(json.dumps({"container_context": [asdict(context) for context in context_container_list]}, indent=2))
        print("===== END CONTEXT OUTPUT =====")



        
