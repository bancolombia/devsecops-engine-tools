from engine_sast.engine_iac.src.domain.model.gateways.tool_gateway import ToolGateway


class IacScan:
    def __init__(self, tool_run: ToolGateway):
        self.tool_run = tool_run

    def process(self):
        return self.tool_run.run_tool()
