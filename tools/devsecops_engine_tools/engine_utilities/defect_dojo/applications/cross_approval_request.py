from devsecops_engine_tools.engine_utilities.defect_dojo.domain.user_case.cross_approval_request import (
    CrossApprovalRequestUserCase,
)
from devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.cross_approval_request import (
    CrossApprovalRequestRestConsumer,
)


class CrossApprovalRequest:
    @staticmethod
    def get_approved_exclusions(session, url: str):
        rest_cross_approval_request = CrossApprovalRequestRestConsumer(session=session)
        use_case = CrossApprovalRequestUserCase(rest_cross_approval_request)
        return use_case.execute(url)