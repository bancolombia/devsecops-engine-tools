from engine_sast.engine_iac.src.domain.model.gateways.remote_config_gateway import RemoteConfigGateway
from engine_sast.engine_iac.src.domain.model.gateways.tool_gateway import ToolGateway


class IacScan:
    def __init__(self, remote_config: RemoteConfigGateway, tool_run: ToolGateway):
        self.remote_config = remote_config
        self.remote_config_json = self.remote_config.get_remote_config().json()
        self.tool_run = tool_run
        self.tool_run.run_tool()

    def process(self):
        print("Init Use case iac_scan")
