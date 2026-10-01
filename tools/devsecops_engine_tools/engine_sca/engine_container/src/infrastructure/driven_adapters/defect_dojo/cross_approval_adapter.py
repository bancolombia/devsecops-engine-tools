from urllib.parse import urlsplit

from devsecops_engine_tools.engine_sca.engine_container.src.domain.model.gateways.cross_approval_gateway import (
    CrossApprovalGateway,
)
from devsecops_engine_tools.engine_utilities.defect_dojo import CrossApprovalRequest
from devsecops_engine_tools.engine_utilities.utils.session_manager import SessionManager


class DefectDojoCrossApprovalAdapter(CrossApprovalGateway):
    def get_approved_exclusions(self, url: str, token: str):
        parsed_url = urlsplit(url)
        host = f"{parsed_url.scheme}://{parsed_url.netloc}"
        session = SessionManager(token, host)
        return CrossApprovalRequest.get_approved_exclusions(session, url)