from engine_core.src.domain.model.gateway.gateway_deserealizator import DeseralizatorGateway
from engine_core.src.domain.model.InputCore import InputCore
from dataclasses import dataclass


@dataclass
class BreakBuild:
    deserializer_gateway : DeseralizatorGateway
    input_core : InputCore
    

    def validate_level_compliance(self):
        vulnerability_list = self.deserializer_gateway.get_list_vulnerability()

