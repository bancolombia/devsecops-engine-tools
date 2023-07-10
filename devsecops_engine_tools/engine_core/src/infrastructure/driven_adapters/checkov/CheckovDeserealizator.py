from engine_core.src.domain.model.gateway.gateway_deserealizator import DeseralizatorGateway
from engine_core.src.domain.model.Vulnerability import Vulnerability


class CheckovDeserealizator(DeseralizatorGateway):
    def get_list_vulnerability(self, results_list, exclusions_list) -> list[Vulnerability]:
        # Implementación personalizada del deserializador
        pass
