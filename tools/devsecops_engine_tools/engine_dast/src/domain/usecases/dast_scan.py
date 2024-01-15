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
import json #BORRAR

class DastScan:
    def __init__(
        self, tool_gateway: ToolGateway, devops_platform_gateway: DevopsPlatformGateway
    ):
        self.tool_gateway = tool_gateway
        self.devops_platform_gateway = devops_platform_gateway

    def process(self, dict_args, secret_tool):
        """
        init_config_tool = self.devops_platform_gateway.get_remote_config(
            dict_args["remote_config_repo"], "DAST/configTools.json"
        )
        """  # DATA PDN
        
        init_config_tool = json.loads(config_tool)  # DATA LOCAL BORRAR
        """
        exclusions = self.devops_platform_gateway.get_remote_config(
            remote_config_repo=dict_args["remote_config_repo"],
            remote_config_path="/DAST/Exclusions/Exclusions.json",
        )
        """  # DATA PDN
        exclusions = json.loads(config_exclusions)  # DATA LOCAL BORRAR
        return self.tool_gateway.run_tool(
            init_config_tool,
            exclusions,
            dict_args["environment"],
            self.devops_platform_gateway.get_variable("pipeline"),
            self.devops_platform_gateway,
            secret_tool,
        )
