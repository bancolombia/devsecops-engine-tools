from devsecops_engine_tools.engine_risk.src.domain.model.gateways.add_epss_gateway import (
    AddEpssGateway,
)

from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


class AddData:
    def __init__(
        self,
        add_epss_gateway: AddEpssGateway,
        findings,
    ):
        self.add_epss_gateway = add_epss_gateway
        self.findings = findings

    def process(self):
        return self.add_epss_gateway.add_epss_data(self.findings)
