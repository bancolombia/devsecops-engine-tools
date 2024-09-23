from devsecops_engine_tools.engine_utilities.utils.api_error import ApiError
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.request_objects.finding import FindingRequest
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.models.finding import Finding, FindingList
from devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.settings.settings import VERIFY_CERTIFICATE
from devsecops_engine_tools.engine_utilities.utils.session_manager import SessionManager
from devsecops_engine_tools.engine_utilities.settings import SETTING_LOGGER
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
import json

logger = MyLogger.__call__(**SETTING_LOGGER).get_logger()


class FindingRestConsumer:
    def __init__(self, session: SessionManager):
        self.__token = session._token
        self.__host = session._host
        self.__session = session._instance

    def get(self, request):
        url = f"{self.__host}/api/v2/findings/"
        headers = {"Authorization": f"Token {self.__token}", "Content-Type": "application/json"}
        response = self.__session.get(url, headers=headers, data={}, params=request, verify=VERIFY_CERTIFICATE)
        if response.status_code != 200:
            raise ApiError(response.json())
        findings = FindingList.from_dict(response.json())
        while response.json().get("next", None):
            next_url = response.json().get("next")
            next_url = next_url.replace("http://", "https://", 1)
            response = self.__session.get(next_url, headers=headers, data={}, verify=VERIFY_CERTIFICATE)
            if response.status_code != 200:
                raise ApiError(response.json())
            findings.results += FindingList.from_dict(response.json()).results
        return findings

    def close(self, request, id):
        url = f"{self.__host}/api/v2/findings/{id}/close/"
        headers = {"Authorization": f"Token {self.__token}", "Content-Type": "application/json"}
        response = self.__session.post(url, headers=headers, data=json.dumps(request), verify=VERIFY_CERTIFICATE)
        if response.status_code != 200:
            logger.error(response.json())
            raise ApiError(response.json())
        logger.debug(response.json())
        logger.debug(response)
        return response
