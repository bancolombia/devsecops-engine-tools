from devsecops_engine_tools.engine_sca.engine_container.src.domain.model.gateways.cross_approval_gateway import (
    CrossApprovalGateway,
)
from devsecops_engine_tools.engine_utilities.defect_dojo import CrossApprovalRequest
from devsecops_engine_tools.engine_utilities.utils.session_manager import SessionManager


class DefectDojoCrossApprovalAdapter(CrossApprovalGateway):
    def get_approved_exclusions(self, host: str, token: str):
        session = SessionManager(token, host)
        return CrossApprovalRequest.get_approved_exclusions(session)