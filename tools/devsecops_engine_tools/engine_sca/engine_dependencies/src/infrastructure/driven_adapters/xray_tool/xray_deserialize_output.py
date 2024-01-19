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
    def get_list_findings(self, dependencies_scanned: list) -> "list[Finding]":
        list_open_vulnerabilities = []
        for dependency in dependencies_scanned:
            with open(dependency, "rb") as file:
                json_data = json.loads(file.read())
                vulnerabilities_data = json_data['vulnerabilities']
                
        return 0