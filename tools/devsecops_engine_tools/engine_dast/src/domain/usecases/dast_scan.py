import json
from devsecops_engine_tools.engine_dast.src.domain.model.gateways.tool_gateway import (
    ToolGateway,
)
from devsecops_engine_tools.engine_dast.src.domain.model.gateways.devops_platform_gateway import (
    DevopsPlatformGateway,
)
from devsecops_engine_tools.engine_dast.src.domain.model.gateways.authentication_method import (
    AuthenticationGateway,
)
from devsecops_engine_tools.engine_dast.src.infrastructure.entry_points.config_dast.config_tool import (
    config_tool_local,
)
from devsecops_engine_tools.engine_dast.src.infrastructure.entry_points.config_dast.config_exclusions import (
    config_exclusions,
)
from devsecops_engine_tools.engine_core.src.domain.model.input_core import (
    InputCore,
)
from devsecops_engine_tools.engine_core.src.domain.model.exclusions import (
    Exclusions,
)
from devsecops_engine_tools.engine_dast.src.domain.model.config_tool import (
    ConfigTool,
)
from devsecops_engine_tools.engine_dast.src.domain.model.target_config import (
    TargetConfig,
)


class DastScan:
    def __init__(
        self, tool_gateway: ToolGateway, 
        devops_platform_gateway: DevopsPlatformGateway,
        authentication_gateway: AuthenticationGateway
    ):
        self.tool_gateway = tool_gateway
        self.devops_platform_gateway = devops_platform_gateway
        self.authentication_gateway = authentication_gateway

    def process_target_data(self, target_file_path):
        with open(target_file_path, "r") as f:
            data = json.load(f)
        target_config = TargetConfig(data)
        return target_config

    def complete_config_tool(
        self, data_file_tool, exclusions, target_file_path, tool
    ) -> (ConfigTool, TargetConfig):
        config_tool = ConfigTool(
            json_data=data_file_tool,
            tool=tool,
        )

        config_tool.exclusions = exclusions
        config_tool.scope_pipeline = self.devops_platform_gateway.get_variable(
            "pipeline"
        )

        if config_tool.exclusions.get("All") is not None:
            config_tool.exclusions_all = config_tool.exclusions.get("All").get(tool)
        if config_tool.exclusions.get(config_tool.scope_pipeline) is not None:
            config_tool.exclusions_scope = config_tool.exclusions.get(
                config_tool.scope_pipeline
            ).get(tool)

        data_target_config = self.process_target_data(
            target_file_path
        )  # configuration for the current target #BORRAR PDN

        return config_tool, data_target_config

    def process(self, dict_args, secret_tool, tool):
        # init_config_tool = self.devops_platform_gateway.get_remote_config(
        #    dict_args["remote_config_repo"], "DAST/configTools.json"
        # )
        # DATA PDN

        init_config_tool = config_tool_local  # DATA LOCAL BORRAR

        # exclusions = self.devops_platform_gateway.get_remote_config(
        #    remote_config_repo=dict_args["remote_config_repo"],
        #    remote_config_path="/DAST/Exclusions/Exclusions.json",
        # )
        # DATA PDN
        exclusions = config_exclusions  # DATA LOCAL BORRAR

        config_tool, target_data = self.complete_config_tool(
            data_file_tool=init_config_tool,
            exclusions=exclusions,
            target_file_path=dict_args["dast_file_path"],
            tool=tool,
        )

        finding_list, path_file_results = self.tool_gateway.run_tool(
            target_data=target_data, config_tool=config_tool, secret_tool=secret_tool
        )

        totalized_exclusions = []
        totalized_exclusions.extend(
            map(lambda elem: Exclusions(**elem), config_tool.exclusions_all)
        ) if config_tool.exclusions_all is not None else None
        totalized_exclusions.extend(
            map(lambda elem: Exclusions(**elem), config_tool.exclusions_scope)
        ) if config_tool.exclusions_scope is not None else None

        input_core = InputCore(
            totalized_exclusions=totalized_exclusions,
            threshold_defined=config_tool.threshold,
            path_file_results=path_file_results,
            custom_message_break_build=config_tool.message_info_dast,
            scope_pipeline=config_tool.scope_pipeline,
            stage_pipeline="Release",
        )

        return finding_list, input_core
