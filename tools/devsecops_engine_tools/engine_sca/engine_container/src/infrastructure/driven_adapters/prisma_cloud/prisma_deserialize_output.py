from devsecops_engine_tools.engine_sca.engine_container.src.domain.model.gateways.deserealizator_gateway import (
    DeseralizatorGateway,
)
from dataclasses import dataclass
from devsecops_engine_tools.engine_utilities.utils.palo_alto_utils import get_palo_alto_findings


@dataclass
class PrismaDeserealizator(DeseralizatorGateway):
    def get_list_findings(self, image_scanned, module="engine_container"):
        return get_palo_alto_findings(image_scanned, module, "PrismaCloud")
