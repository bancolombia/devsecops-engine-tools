import json
from devsecops_engine_utilities.utils.validation_error import ValidationError
from devsecops_engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_utilities.defect_dojo.domain.request_objects.import_scan import ImportScanRequest
from devsecops_engine_utilities.defect_dojo.infraestructure.driver_adapters.settings.settings import VERIFY_CERTIFICATE
from devsecops_engine_utilities.utils.session_manager import SessionManager
from datetime import datetime

logger = MyLogger.__call__().get_logger()


class EngagementRestConsumer:
    def __init__(self, token: str, host: str, session: SessionManager):
        self.__token = token
        self.__host = host
        self.__session = session

    def get_engagement(self, product_name):
        url = f"{self.__host}/api/v2/engagements/"

        data = json.dumps({"name": product_name})

        headers = {"Authorization": f"Token {self.__token}", "Content-Type": "application/json"}

        response = self.__session.get(url=url, headers=headers, data=data, verify=VERIFY_CERTIFICATE)
        if response.status_code != 200:
            raise ValidationError(response)

        return response.json()

    def post_engagement(self, engagement_name, product_id):
        url = f"{self.__host}/api/v2/engagements/"
        data = json.dumps(
            {
                "name": engagement_name,
                "target_start": str(datetime.now().date()),
                "target_end": str(datetime.now().date()),
                "product": product_id,
            }
        )
        headers = {"Authorization": f"Token {self.__token}", "Content-Type": "application/json"}
        response = self.__session.post(url=url, headers=headers, data=data, verify=VERIFY_CERTIFICATE)
        if response.status_code != 201:
            raise ValidationError(response)
        logger.info(response)

        return response.json()
