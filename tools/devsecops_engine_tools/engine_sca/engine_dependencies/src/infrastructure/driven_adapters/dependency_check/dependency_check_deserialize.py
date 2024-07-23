from devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.model.gateways.deserializator_gateway import (
    DeserializatorGateway,
)
from devsecops_engine_tools.engine_core.src.domain.model.finding import (
    Finding,
    Category,
)
from dataclasses import dataclass
from datetime import datetime

@dataclass
class DependencyCheckDeserialize(DeserializatorGateway):

    def get_list_findings(self, dependencies_scanned_file) -> "list[Finding]":
        list_open_vulnerabilities = []
        for dependency in dependencies_scanned_file.get("dependencies", []):
            for package in dependency.get("packages", []):
                where = package.get("id")

            for vulnerability in dependency.get("vulnerabilities", []):
                description = vulnerability["name"]
                severity = vulnerability["severity"]
                finding_open = Finding(
                    id = "DEPENDENCY-CHECK",
                    cvss = None,
                    where = where,
                    description = description,
                    severity = severity.lower(),
                    identification_date=datetime.now().strftime("%d%m%Y"),
                    published_date_cve=None,
                    module="engine_dependencies",
                    category=Category.VULNERABILITY,
                    requirements=None,
                    tool = "dependency-check"
                )
                list_open_vulnerabilities.append(finding_open)

        return list_open_vulnerabilities
