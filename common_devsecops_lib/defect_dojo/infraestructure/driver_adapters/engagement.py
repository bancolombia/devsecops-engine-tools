import requests
import json
from helper.validation_error import ValidationError
from helper.logger_info import MyLogger
from defect_dojo.domain.request_objects.import_scan import ImportScanRequest
from defect_dojo.infraestructure.driver_adapters.settings.settings import VERIFY_CERTIFICATE
from datetime import datetime

logger = MyLogger.__call__().get_logger()


class EngagementRestConsumer:
    def __init__(self, token: str, host: str):
        self.__token = token
        self.__host = host

    def get_engagement(self, request: ImportScanRequest):
        url = f"{self.__host}/api/v2/engagements/"

        data = json.dumps({"name": request.product_name})

        headers = {"Authorization": f"Token {self.__token}", "Content-Type": "application/json"}

        response = requests.request("GET", url=url, headers=headers, data=data, verify=VERIFY_CERTIFICATE)
        if response.status_code != 200:
            raise ValidationError(response)

        return response.json()

    def post_engagement(self, request: ImportScanRequest, product_id):
        url = f"{self.__host}/api/v2/engagements/"
        data = json.dumps(
            {
                "name": request.engagement_name,
                "target_start": str(datetime.now().date()),
                "target_end": str(datetime.now().date()),
                "product": product_id,
            }
        )
        headers = {"Authorization": f"Token {self.__token}", "Content-Type": "application/json"}
        response = requests.request("POST", url=url, headers=headers, data=data, verify=VERIFY_CERTIFICATE)
        if response.status_code != 201:
            raise ValidationError(response)
        logger.info(response)

        return response.json()
