from devsecops_engine_tools.engine_risk.src.domain.model.gateways.add_epss_gateway import (
    AddEpssGateway,
)


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
