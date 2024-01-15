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
        return 0