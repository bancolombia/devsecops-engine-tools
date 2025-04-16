from devsecops_engine_tools.engine_utilities.utils.api_error import ApiError
import json
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.request_objects.import_scan import ImportScanRequest
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.models.scan_configuration import (
    ScanConfiguration,
    ScanConfigurationList,
)
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.models.scan_configuration import ScanConfiguration
from devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.settings.settings import VERIFY_CERTIFICATE
from devsecops_engine_tools.engine_utilities.utils.session_manager import SessionManager
from devsecops_engine_tools.engine_utilities.settings import SETTING_LOGGER

logger = MyLogger.__call__(**SETTING_LOGGER).get_logger()


class ScanConfigrationRestConsumer:
    def __init__(self, request: ImportScanRequest, session: SessionManager) -> ScanConfiguration:
        self.__token = request.token_defect_dojo
        self.__host = request.host_defect_dojo
        self.__session = session._instance

    def post_api_scan_configuration(
        self, request: ImportScanRequest, product_id: int, tool_configuration_id: int
    ) -> ScanConfiguration:
        url = f"{self.__host}/api/v2/product_api_scan_configurations/"

        headers = {
            "Authorization": f"Token {self.__token}",
            "Content-Type": "application/json",
        }

        data = json.dumps(
            {
                "service_key_1": request.engagement_name,
                "product": product_id,
                "tool_configuration": tool_configuration_id,
            }
        )
        try:
            response = self.__session.post(url=url, headers=headers, data=data, verify=VERIFY_CERTIFICATE)
            if response.status_code != 201:
                logger.error(response.json())
                raise ApiError(response.json())
            scan_configuration_object = ScanConfiguration.from_dict(response.json())
        except Exception as e:
            logger.error(f"from dict scanConfiguration {response.json()}")
            raise ApiError(e)
        return scan_configuration_object

    def get_api_scan_configuration(self, request: ImportScanRequest, product_id) -> ScanConfigurationList:
        url = f"{self.__host}/api/v2/product_api_scan_configurations/?service_key_1={request.engagement_name}&product={product_id}"
        headers = {
            "Authorization": f"Token {self.__token}",
            "Conten-Type": "application/json",
        }
        try:
            response = self.__session.get(url=url, headers=headers, verify=VERIFY_CERTIFICATE)
            if response.status_code != 200:
                logger.error(response.json())
                raise ApiError(response.json())
            response = ScanConfigurationList.from_dict(response.json())
        except Exception as e:
            raise ApiError(e)
        return response
