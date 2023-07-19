import json
from devsecops_engine_utilities.utils.validation_error import ValidationError
from devsecops_engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_utilities.defect_dojo.domain.request_objects.import_scan import ImportScanRequest
from devsecops_engine_utilities.defect_dojo.infraestructure.driver_adapters.settings.settings import VERIFY_CERTIFICATE
from devsecops_engine_utilities.defect_dojo.domain.models.engagement import Engagement, EngagementList
from devsecops_engine_utilities.utils.session_manager import SessionManager
from datetime import datetime
from devsecops_engine_utilities.settings import DEBUG

logger = MyLogger.__call__(debug=DEBUG).get_logger()


class EngagementRestConsumer:
    def __init__(self, request: ImportScanRequest, session: SessionManager):
        self.__token = request.token_defect_dojo
        self.__host = request.host_defect_dojo
        self.__session = session

    def get_engagements(self, engagement_name):
        url = f"{self.__host}/api/v2/engagements/?name={engagement_name}"

        headers = {"Authorization": f"Token {self.__token}", "Content-Type": "application/json"}

        response = self.__session.get(url=url, headers=headers, verify=VERIFY_CERTIFICATE)
        if response.status_code != 200:
            logger.error(response.json())
            raise ValidationError(response)
        response = EngagementList().from_dict(response.json())
        return response

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
            logger.error(response.json())
            raise ValidationError(response)
        response = Engagement().from_dict(response.json())
        return response
