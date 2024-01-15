from devsecops_engine_tools.engine_dast.src.domain.model.gateways.tool_gateway import (
    ToolGateway,
)
from devsecops_engine_tools.engine_dast.src.domain.model.gateways.devops_platform_gateway import (
    DevopsPlatformGateway,
)
from devsecops_engine_tools.engine_dast.src.infrastructure.entry_points.config_dast.config_tool import (
    config_tool,
)
from devsecops_engine_tools.engine_dast.src.infrastructure.entry_points.config_dast.config_exclusions import (
    config_exclusions,
)


class DastScan:
    def __init__(
        self, tool_gateway: ToolGateway, devops_platform_gateway: DevopsPlatformGateway
    ):
        self.tool_gateway = tool_gateway
        self.devops_platform_gateway = devops_platform_gateway

    def process(self, dict_args, secret_tool):
        
        init_config_tool = self.devops_platform_gateway.get_remote_config(
            dict_args["remote_config_repo"], "DAST/configTools.json"
        )
          # DATA PDN

        exclusions = self.devops_platform_gateway.get_remote_config(
            remote_config_repo=dict_args["remote_config_repo"],
            remote_config_path="/DAST/Exclusions/Exclusions.json",
        )
          # DATA PDN

        return self.tool_gateway.run_tool(
            init_config_tool=init_config_tool,
            target_file_path=dict_args["dast_file_path"],
            exclusions=exclusions,
            environment=dict_args["environment"],
            pipeline=self.devops_platform_gateway.get_variable("pipeline"),
            secret_tool=secret_tool
        )
