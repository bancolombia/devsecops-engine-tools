from devsecops_engine_utilities.defect_dojo.domain.request_objects.finding import FindingRequest
from devsecops_engine_utilities.defect_dojo.infraestructure.driver_adapters.finding import FindingRestConsumer
from devsecops_engine_utilities.defect_dojo.domain.user_case.finding import FindingUserCase
from devsecops_engine_utilities.utils.session_manager import SessionManager
from devsecops_engine_utilities.utils.api_error import ApiError


class Finding:
    @staticmethod
    def close_finding(unique_id_from_tool, session):
        try:
            request = FindingRequest(unique_id_from_tool=unique_id_from_tool)
            rest_finding = FindingRestConsumer(session=session)
            uc = FindingUserCase(rest_finding)
            uc.execute(request)

        except ApiError as e:
            return e
