from urllib.parse import urljoin

from devsecops_engine_tools.engine_utilities.defect_dojo.domain.models.cross_approval_request import (
    CrossApprovalRequestList,
)
from devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.settings.settings import (
    VERIFY_CERTIFICATE,
)
from devsecops_engine_tools.engine_utilities.settings import SETTING_LOGGER
from devsecops_engine_tools.engine_utilities.utils.api_error import ApiError
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities.utils.session_manager import SessionManager

logger = MyLogger.__call__(**SETTING_LOGGER).get_logger()


class CrossApprovalRequestRestConsumer:
    def __init__(self, session: SessionManager):
        self.__token = session._token
        self.__session = session._instance

    def get_cross_approval_requests(self, url: str) -> CrossApprovalRequestList:
        headers = {
            "Authorization": f"Token {self.__token}",
            "Accept": "application/json",
        }
        try:
            response = self.__session.get(
                url, headers=headers, verify=VERIFY_CERTIFICATE
            )
            if response.status_code != 200:
                raise ApiError(response.json())

            response_data = response.json()
            requests = CrossApprovalRequestList.from_dict(response_data)
            while response_data.get("next"):
                next_url = urljoin(url, response_data["next"])
                response = self.__session.get(
                    next_url, headers=headers, verify=VERIFY_CERTIFICATE
                )
                if response.status_code != 200:
                    raise ApiError(response.json())
                response_data = response.json()
                requests.results.extend(
                    CrossApprovalRequestList.from_dict(response_data).results
                )
            return requests
        except Exception as error:
            logger.error("Error getting cross approval requests: %s", error)
            if isinstance(error, ApiError):
                raise
            raise ApiError(error) from error