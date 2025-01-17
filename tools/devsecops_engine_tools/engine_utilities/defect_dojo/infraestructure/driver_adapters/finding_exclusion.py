from devsecops_engine_tools.engine_utilities.utils.api_error import ApiError
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.models.finding_exclusion import FindingExclusionList
from devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.settings.settings import VERIFY_CERTIFICATE
from devsecops_engine_tools.engine_utilities.utils.session_manager import SessionManager
from devsecops_engine_tools.engine_utilities.settings import SETTING_LOGGER

logger = MyLogger.__call__(**SETTING_LOGGER).get_logger()

class FindingExclusionRestConsumer:
    def __init__(self, session: SessionManager):
        self.__token = session._token
        self.__host = session._host
        self.__session = session._instance


    def get_finding_exclusions(self, request) -> FindingExclusionList:
        url = f"{self.__host}/api/v2/finding_exclusions/"
        headers = {"Authorization": f"Token {self.__token}", "Content-Type": "application/json"}
        try:
            response = self.__session.get(url, headers=headers, params=request, verify=VERIFY_CERTIFICATE)
            if response.status_code != 200:
                raise ApiError(response.json())
            finding_exclusions_object = FindingExclusionList.from_dict(response.json())
        except Exception as e:
            logger.error(f"from dict FindingExclusion: {e}")
            raise ApiError(e)
        return finding_exclusions_object
