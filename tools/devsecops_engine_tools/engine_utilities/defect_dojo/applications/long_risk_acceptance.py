from devsecops_engine_tools.engine_utilities.utils.api_error import ApiError
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.user_case.long_risk_acceptance import (
    LongRiskAcceptanceUserCase,
)
from devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.long_risk_acceptance import (
    LongRiskAcceptanceRestConsumer,
)
from devsecops_engine_tools.engine_utilities.settings import SETTING_LOGGER

logger = MyLogger.__call__(**SETTING_LOGGER).get_logger()


class LongRiskAcceptance:
    @staticmethod
    def get_long_risk_acceptance(session, long_risk_acceptance_id):
        try:
            rest_long_risk_acceptance = LongRiskAcceptanceRestConsumer(session=session)

            uc = LongRiskAcceptanceUserCase(rest_long_risk_acceptance)
            return uc.execute(long_risk_acceptance_id)
        except ApiError as e:
            logger.error(f"Error during get long risk acceptance: {e}")
            raise e
