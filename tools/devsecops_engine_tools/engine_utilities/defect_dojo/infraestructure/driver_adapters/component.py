import json
from devsecops_engine_tools.engine_utilities.utils.api_error import ApiError
from devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.settings.settings import VERIFY_CERTIFICATE
from devsecops_engine_tools.engine_utilities.utils.session_manager import SessionManager
from devsecops_engine_tools.engine_utilities.settings import SETTING_LOGGER
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger

from devsecops_engine_tools.engine_utilities.defect_dojo.domain.models.component import ComponentList, Component

logger = MyLogger.__call__(**SETTING_LOGGER).get_logger()


class ComponentRestConsumer:
    def __init__(self, session: SessionManager):
        self.__token = session._token
        self.__host = session._host
        self.__session = session._instance

    def get_component(self, request):
        url = f"{self.__host}/api/v2/components/"
        headers = {
            "Authorization": f"Token {self.__token}",
            "Content-Type": "application/json",
        }
        try:
            response = self.__session.get(
                url=url, headers=headers, params=request, verify=VERIFY_CERTIFICATE
            )
            if response.status_code != 200:
                logger.error(response.json())
                raise ApiError(response.json())
            components = ComponentList().from_dict(response.json())
        except Exception as e:
            raise ApiError(e)
        return components
    
    def post_component(self, request):
        url = f"{self.__host}/api/v2/components/"
        headers = {
            "Authorization": f"Token {self.__token}",
            "Content-Type": "application/json",
        }
        try:
            response = self.__session.post(
                url=url, headers=headers, data=json.dumps(request), verify=VERIFY_CERTIFICATE
            )
            if response.status_code != 201:
                raise ApiError(response.json())
            response = Component.from_dict(response.json())
        except Exception as e:
            raise ApiError(e)
        return response
