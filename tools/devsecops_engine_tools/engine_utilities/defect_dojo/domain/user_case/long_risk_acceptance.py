from devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.long_risk_acceptance import (
    LongRiskAcceptanceRestConsumer,
)


class LongRiskAcceptanceUserCase:
    def __init__(self, rest_long_risk_acceptance: LongRiskAcceptanceRestConsumer):
        self.__rest_long_risk_acceptance = rest_long_risk_acceptance

    def execute(self, long_risk_acceptance_id):
        return self.__rest_long_risk_acceptance.get_long_risk_acceptance(
            long_risk_acceptance_id
        )
