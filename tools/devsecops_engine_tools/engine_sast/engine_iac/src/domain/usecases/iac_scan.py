from devsecops_engine_tools.engine_sast.engine_iac.src.domain.model.gateways.tool_gateway import (
    ToolGateway,
)
from devsecops_engine_tools.engine_sast.engine_iac.src.domain.model.gateways.devops_platform_gateway import (
    DevopsPlatformGateway,
)


class IacScan:
    def __init__(
        self, tool_gateway: ToolGateway, devops_platform_gateway: DevopsPlatformGateway
    ):
        self.tool_gateway = tool_gateway
        self.devops_platform_gateway = devops_platform_gateway

    def process(self, dict_args, secret_tool):
        config_tool = self.devops_platform_gateway.get_remote_config(
            dict_args["remote_config_repo"], "SAST/IAC/configTools.json"
        )

        exclusions = self.devops_platform_gateway.get_remote_config(
            remote_config_repo=dict_args["remote_config_repo"],
            remote_config_path="/SAST/IAC/Exclusions/Exclusions.json",
        )
        return self.tool_gateway.run_tool(
            config_tool,
            exclusions,
            dict_args["environment"],
            self.devops_platform_gateway.get_variable("pipeline"),
            secret_tool,
        )
