from devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.model.gateways.deserializator_gateway import (
    DeserializatorGateway,
)
from devsecops_engine_tools.engine_core.src.domain.model.finding import (
    Finding,
    Category,
)
from dataclasses import dataclass
from datetime import datetime
import json
import os
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()

@dataclass
class DependencyCheckDeserialize(DeserializatorGateway):

    def get_list_findings(self, dependencies_scanned_file) -> "list[Finding]":
        filename, extension = os.path.splitext(dependencies_scanned_file)
        if extension.lower() != ".json":
            dependencies_scanned_file = f"{filename}.json"

        data_result = self.load_results(dependencies_scanned_file)

        list_open_vulnerabilities = []
        for dependency in data_result.get("dependencies", []):
            for vulnerability in dependency.get("vulnerabilities", []):
                vulnerable_software = vulnerability.get("vulnerableSoftware", [])
                fix = (
                    vulnerable_software[0]
                    .get("software", {})
                    .get("versionEndExcluding", None)
                    if vulnerable_software
                    else None
                )
                finding_open = Finding(
                    id=vulnerability["name"][:20],
                    cvss=str(vulnerability.get("cvssv3", {})),
                    where=dependency.get("fileName").split(':')[-1].strip(),
                    description=vulnerability["description"][:170].replace("\n\n", " "),
                    severity=vulnerability["severity"].lower(),
                    identification_date=datetime.now().strftime("%d%m%Y"),
                    published_date_cve=None,
                    module="engine_dependencies",
                    category=Category.VULNERABILITY,
                    requirements=fix,
                    tool="DEPENDENCY_CHECK"
                )
                list_open_vulnerabilities.append(finding_open)

        return list_open_vulnerabilities
    
    def load_results(self, dependencies_scanned_file):
        try:
            with open(dependencies_scanned_file) as f:
                data = json.load(f)
            return data
        except Exception as ex:
            logger.error(f"An error ocurred loading dependency-check results {ex}")
            return None
