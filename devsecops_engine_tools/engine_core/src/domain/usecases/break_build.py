from engine_core.src.domain.model.gateway.gateway_deserealizator import DeseralizatorGateway
from engine_core.src.domain.model.InputCore import InputCore
from dataclasses import dataclass


@dataclass
class BreakBuild:
    deserializer_gateway : DeseralizatorGateway
    input_core : InputCore
    

    def validate_level_compliance(self):
        vulnerability_list = self.deserializer_gateway.get_list_vulnerability()
        level_compliance = self.input_core.level_compliance_defined
        exclusions = self.input_core.totalized_exclusions
        rules_scaned = self.input_core.rules_scaned

        if len(vulnerability_list) != 0:
            print()
        else:
            return len(vulnerability_list)
