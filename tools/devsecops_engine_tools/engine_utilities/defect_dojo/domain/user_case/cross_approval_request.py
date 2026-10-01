from datetime import date, datetime

from devsecops_engine_tools.engine_utilities.defect_dojo.domain.models.cross_approval_request import (
    CrossApprovalRequestList,
)
from devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.cross_approval_request import (
    CrossApprovalRequestRestConsumer,
)


class CrossApprovalRequestUserCase:
    def __init__(self, rest_cross_approval_request: CrossApprovalRequestRestConsumer):
        self.__rest_cross_approval_request = rest_cross_approval_request

    def execute(self, url: str):
        response = self.__rest_cross_approval_request.get_cross_approval_requests(url)
        return [
            exclusion
            for request in response.results
            if request.status.lower() == "approved"
            for exclusion in request.exclusions
            if self._is_current(exclusion.expired_at, exclusion.expired_date)
        ]

    @staticmethod
    def _is_current(expired_at, expired_date):
        if expired_at:
            return False
        if not expired_date:
            return True
        try:
            expiration_date = datetime.strptime(expired_date, "%d%m%Y").date()
        except ValueError:
            return False
        return expiration_date >= date.today()