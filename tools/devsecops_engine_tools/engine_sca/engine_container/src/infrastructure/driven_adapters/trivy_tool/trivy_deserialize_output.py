from devsecops_engine_tools.engine_sca.engine_container.src.domain.model.context_container import (
    ContextContainer,
)
from devsecops_engine_tools.engine_sca.engine_container.src.domain.model.gateways.deserealizator_gateway import (
    DeseralizatorGateway,
)
from devsecops_engine_tools.engine_core.src.domain.model.finding import (
    Finding,
    Category,
)
from dataclasses import asdict, dataclass
import json
from datetime import datetime, timezone


@dataclass
class TrivyDeserializator(DeseralizatorGateway):

    def get_list_findings(self, image_scanned) -> "list[Finding]":
        list_open_vulnerabilities = []
        with open(image_scanned, "rb") as file:
            image_object = file.read()
            json_data = json.loads(image_object)
            vulnerabilities_data = json_data["Results"][0].get("Vulnerabilities", [])
            vulnerabilities = [
                Finding(
                    id=vul.get("VulnerabilityID", ""),
                    cvss=str(
                        next(
                            (
                                v["V3Score"]
                                for v in vul["CVSS"].values()
                                if "V3Score" in v
                            ),
                            None,
                        )
                    ),
                    where=vul.get("PkgName", "")
                    + " "
                    + vul.get("InstalledVersion", ""),
                    description=vul.get("Description", "").replace("\n", "")[:150],
                    severity=vul.get("Severity", "").lower(),
                    identification_date=datetime.now().strftime("%Y-%m-%dT%H:%M:%S%z"),
                    published_date_cve=self._check_date_format(vul),
                    module="engine_container",
                    category=Category.VULNERABILITY,
                    requirements=vul.get("FixedVersion") or vul.get("Status", ""),
                    tool="Trivy",
                )
                for vul in vulnerabilities_data
                if vul.get("CVSS") and vul.get("PublishedDate")
            ]
            list_open_vulnerabilities.extend(vulnerabilities)
        return list_open_vulnerabilities

    def get_container_context_from_results(
        self, image_scanned
    ) -> "list[ContextContainer]":
        context_container_list = []

        with open(image_scanned, "rb") as file:
            image_object = file.read()
            json_data = json.loads(image_object)

        results = json_data.get("Results", [])

        for result in results:
            vulnerabilities = result.get("Vulnerabilities", [])
            for vul in vulnerabilities:
                context_container = ContextContainer(
                    cve_id=vul.get("VulnerabilityID", "unknown"),
                    cwe_id=vul.get("CweIDs", "unknown"),
                    vendor_id=vul.get("VendorIDs", "unknown"),
                    severity=vul.get("Severity", "unknown").lower(),
                    vulnerability_status=vul.get("Status", "unknown"),
                    target_image=result.get("Target", "unknown"),
                    package_name=vul.get("PkgName", "unknown"),
                    installed_version=vul.get("InstalledVersion", "unknown"),
                    fixed_version=vul.get("FixedVersion", "unknown"),
                    cvss_score=next(
                        (
                            v.get("V3Score", "unknown")
                            for v in vul.get("CVSS", {}).values()
                            if "V3Score" in v
                        ),
                        None,
                    ),
                    cvss_vector=vul.get("CVSS", "unknown"),
                    description=vul.get("Description", "unknown").replace("\n", ""),
                    os_type=result.get("Type", "unknown"),
                    layer_digest=vul.get("Layer", {}).get("DiffID", "unknown"),
                    published_date=(
                        self._check_date_format(vul)
                        if vul.get("PublishedDate")
                        else None
                    ),
                    last_modified_date=vul.get("LastModifiedDate", "unknown"),
                    references=vul.get("References", "unknown"),
                    source_tool="Trivy",
                )
                context_container_list.append(context_container)

        print("===== BEGIN CONTEXT OUTPUT =====")
        print(
            json.dumps(
                {
                    "container_context": [
                        asdict(context) for context in context_container_list
                    ]
                },
                indent=2,
            )
        )
        print("===== END CONTEXT OUTPUT =====")

    def _check_date_format(self, vul):
        try:
            published_date_cve = (
                datetime.strptime(vul.get("PublishedDate"), "%Y-%m-%dT%H:%M:%S.%fZ")
                .replace(tzinfo=timezone.utc)
                .isoformat()
            )
        except:
            published_date_cve = (
                datetime.strptime(vul.get("PublishedDate"), "%Y-%m-%dT%H:%M:%SZ")
                .replace(tzinfo=timezone.utc)
                .isoformat()
            )
        return published_date_cve