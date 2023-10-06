from devsecops_engine_utilities.utils.api_error import ApiError
from devsecops_engine_utilities.defect_dojo.domain.request_objects.finding import FindingRequest
from devsecops_engine_utilities.defect_dojo.infraestructure.driver_adapters.settings.settings import VERIFY_CERTIFICATE
from devsecops_engine_utilities.utils.session_manager import SessionManager
from devsecops_engine_utilities.settings import SETTING_LOGGER
from devsecops_engine_utilities.utils.logger_info import MyLogger

logger = MyLogger.__call__(**SETTING_LOGGER).get_logger()


class FindingRestConsumer:
    def __init__(self, session: SessionManager):
        self.__token = session._token
        self.__host = session._host
        self.__session = session

    def get(self, request: FindingRequest):
        url = f"{self.__host}/api/v2/engagements/?unique_id_from_tool={request.unique_id_from_tool}"
        headers = {"Authorization": f"Token {self.__token}", "Content-Type": "application/json"}
        try:
            response = self.__session.get(url, headers=headers, data={}, verify=VERIFY_CERTIFICATE)
            if response.status_code != 200:
                raise ApiError(response.json())
            products_object = ProductList.from_dict(response.json())
        except Exception as e:
            logger.error(f"from dict product: {response.json()}")
            raise ApiError(e)
        return products_object
