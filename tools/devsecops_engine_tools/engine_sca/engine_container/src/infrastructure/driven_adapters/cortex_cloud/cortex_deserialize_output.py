from dataclasses import dataclass

from devsecops_engine_tools.engine_sca.engine_container.src.domain.model.gateways.deserealizator_gateway import (
    DeseralizatorGateway,
)
from devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.helpers.twistcli_findings_helper import (
    deserialize_twistcli_findings,
)


@dataclass
class CortexDeserealizator(DeseralizatorGateway):
    def get_list_findings(self, image_scanned, module="engine_container"):
        return deserialize_twistcli_findings(
            image_scanned=image_scanned,
            module=module,
            tool_name="CortexCloud",
        )
