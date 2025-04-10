import json
from devsecops_engine_tools.engine_utilities.utils.api_error import ApiError
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.request_objects.import_scan import (
    ImportScanRequest,
)
from devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.settings.settings import (
    VERIFY_CERTIFICATE,
)
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.models.engagement import (
    Engagement,
    EngagementList,
)
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
        request = {"name": engagement_name}
        return self.get_engagements_by_request(request)

    def get_engagements_by_request(self, request):
        url = f"{self.__host}/api/v2/engagements/"
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
            engagements = EngagementList().from_dict(response.json())
            while response.json().get("next", None):
                next_url = response.json().get("next")
                next_url = next_url.replace("http://", "https://", 1)
                response = self.__session.get(
                    next_url, headers=headers, data={}, verify=VERIFY_CERTIFICATE
                )
                if response.status_code != 200:
                    raise ApiError(response.json())
                engagements.results += (
                    EngagementList().from_dict(response.json()).results
                )
        except Exception as e:
            raise ApiError(e)
        return engagements

    def post_engagement(self, request: ImportScanRequest, product_id, tool_scm_configuration_id):
        url = f"{self.__host}/api/v2/engagements/"
        data = {
                "name": request.engagement_name,
                "target_start": str(datetime.now().date()),
                "target_end": str(datetime.now().date()),
                "product": product_id,
                "engagement_type": "CI/CD",
                "status": "In Progress",
            }
        
        if request.source_code_management_uri:
            data["source_code_management_uri"] = request.source_code_management_uri

        if tool_scm_configuration_id:
            data["source_code_management_server"] = tool_scm_configuration_id
        
        headers = {
            "Authorization": f"Token {self.__token}",
            "Content-Type": "application/json",
        }
        try:
            response = self.__session.post(
                url=url, headers=headers, data=json.dumps(data), verify=VERIFY_CERTIFICATE
            )
            if response.status_code != 201:
                logger.error(response.json())
                raise ApiError(response.json())
            response = Engagement().from_dict(response.json())
        except Exception as e:
            raise ApiError(e)
        return response
