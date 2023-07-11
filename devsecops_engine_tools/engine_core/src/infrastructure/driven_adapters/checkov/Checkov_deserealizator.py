from engine_core.src.domain.model.gateway.gateway_deserealizator import DeseralizatorGateway
from engine_core.src.domain.model.Vulnerability import Vulnerability


class CheckovDeserealizator(DeseralizatorGateway):
    @staticmethod
    def get_list_vulnerability(results_list) -> list[Vulnerability]:
        # Implementación personalizada del deserializador
        print(results_list)
        pass
