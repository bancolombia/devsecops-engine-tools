import json
from devsecops_engine_tools.engine_utilities.utils.api_error import ApiError
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.request_objects.import_scan import ImportScanRequest
from devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.settings.settings import VERIFY_CERTIFICATE
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.models.engagement import Engagement, EngagementList
from devsecops_engine_tools.engine_utilities.utils.session_manager import SessionManager
from datetime import datetime
from devsecops_engine_tools.engine_utilities.settings import SETTING_LOGGER

logger = MyLogger.__call__(**SETTING_LOGGER).get_logger()


class EngagementRestConsumer:
    def __init__(self, request: ImportScanRequest, session: SessionManager):
        self.__token = request.token_defect_dojo
        self.__host = request.host_defect_dojo
        self.__session = session._instance

    def get_engagements(self, engagement_name):
        url = f"{self.__host}/api/v2/engagements/?name={engagement_name}"

        headers = {"Authorization": f"Token {self.__token}", "Content-Type": "application/json"}
        try:
            response = self.__session.get(url=url, headers=headers, verify=VERIFY_CERTIFICATE)
            if response.status_code != 200:
                logger.error(response.json())
                raise ApiError(response.json())
            response = EngagementList().from_dict(response.json())
        except Exception as e:
            raise ApiError(e)
        return response

    def post_engagement(self, engagement_name, product_id):
        url = f"{self.__host}/api/v2/engagements/"
        data = json.dumps(
            {
                "name": engagement_name,
                "target_start": str(datetime.now().date()),
                "target_end": str(datetime.now().date()),
                "product": product_id,
                "engagement_type": "CI/CD",
                "status": "In Progress",
            }
        )
        headers = {"Authorization": f"Token {self.__token}", "Content-Type": "application/json"}
        try:
            response = self.__session.post(url=url, headers=headers, data=data, verify=VERIFY_CERTIFICATE)
            if response.status_code != 201:
                logger.error(response.json())
                raise ApiError(response.json())
            response = Engagement().from_dict(response.json())
        except Exception as e:
            raise ApiError(e)
        return response
