from devsecops_engine_tools.engine_utilities.utils.api_error import ApiError
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.models.long_risk_acceptance import (
    LongRiskAcceptance,
)
from devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.settings.settings import (
    VERIFY_CERTIFICATE,
)
from devsecops_engine_tools.engine_utilities.utils.session_manager import SessionManager
from devsecops_engine_tools.engine_utilities.settings import SETTING_LOGGER

logger = MyLogger.__call__(**SETTING_LOGGER).get_logger()


class LongRiskAcceptanceRestConsumer:
    def __init__(self, session: SessionManager):
        self.__token = session._token
        self.__host = session._host
        self.__session = session._instance

    def get_long_risk_acceptance(self, long_risk_acceptance_id) -> LongRiskAcceptance:
        url = f"{self.__host}/api/v2/long_risk_acceptance/{long_risk_acceptance_id}/"
        headers = {
            "Authorization": f"Token {self.__token}",
            "Content-Type": "application/json",
        }
        try:
            response = self.__session.get(
                url, headers=headers, verify=VERIFY_CERTIFICATE
            )
            if response.status_code != 200:
                raise ApiError(response.json())
            return LongRiskAcceptance.from_dict(response.json())
        except Exception as e:
            logger.error(f"from dict LongRiskAcceptance: {e}")
            raise ApiError(e)
