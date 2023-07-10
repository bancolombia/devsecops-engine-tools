import requests
import json
from devsecops_engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_utilities.utils.validation_error import ValidationError
from devsecops_engine_utilities.defect_dojo.domain.request_objects.import_scan import ImportScanRequest
from devsecops_engine_utilities.defect_dojo.domain.models.scan_configuration import ScanConfiguration
from devsecops_engine_utilities.defect_dojo.infraestructure.driver_adapters.settings.settings import VERIFY_CERTIFICATE

logger = MyLogger.__call__().get_logger()


class ScanConfigrationRestConsumer:
    def __init__(self, request: ImportScanRequest):
        self.__token = request.token_defect_dojo
        self.__host = request.host_defect_dojo

    def post_api_scan_configuration(self, request: ImportScanRequest, product_id: int, tool_configuration_id: int):
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

        response = requests.request("POST", url=url, headers=headers, data=data, verify=VERIFY_CERTIFICATE)
        if response.status_code != 201:
            raise ValidationError(response)
        scan_configuration_object = ScanConfiguration.from_dict(response.json())
        return scan_configuration_object
