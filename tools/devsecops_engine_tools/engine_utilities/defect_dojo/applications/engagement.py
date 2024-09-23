from devsecops_engine_tools.engine_utilities.utils.api_error import ApiError
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.user_case.engagement import EngagementUserCase
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.request_objects.import_scan import ImportScanRequest
from devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.engagement import EngagementRestConsumer
from devsecops_engine_tools.engine_utilities.utils.session_manager import SessionManager

class Engagement:
    @staticmethod
    def get_engagements(request_is: ImportScanRequest, request: dict):
        try:
            rest_engagement = EngagementRestConsumer(request_is, session=SessionManager())

            uc = EngagementUserCase(rest_engagement)
            return uc.execute(request)
        except ApiError as e:
            raise e