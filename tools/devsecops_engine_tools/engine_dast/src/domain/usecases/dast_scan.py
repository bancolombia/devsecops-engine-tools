from typing import (
    List, Tuple, Any
)
from devsecops_engine_tools.engine_dast.src.domain.model.gateways.tool_gateway import (
    ToolGateway,
)
from devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway import (
    DevopsPlatformGateway,
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

class DastScan:
    def __init__(
        self,
        tool_gateway: ToolGateway,
        devops_platform_gateway: DevopsPlatformGateway,
        data_target,
        aditional_tools: "List[ToolGateway]"
    ):
        self.tool_gateway = tool_gateway
        self.devops_platform_gateway = devops_platform_gateway
        self.data_target = data_target
        self.other_tools = aditional_tools

    def complete_config_tool(
        self, data_file_tool, exclusions, tool
    ) -> "Tuple[ConfigTool, Any]":
        config_tool = ConfigTool(
            json_data=data_file_tool,
            tool=tool,
        )

        config_tool.exclusions = exclusions
        config_tool.scope_pipeline = self.devops_platform_gateway.get_variable(
            "pipeline_name"
        )

        if config_tool.exclusions.get("All") is not None:
            config_tool.exclusions_all = config_tool.exclusions.get("All").get(
                tool
            )
        if config_tool.exclusions.get(config_tool.scope_pipeline) is not None:
            config_tool.exclusions_scope = config_tool.exclusions.get(
                config_tool.scope_pipeline
            ).get(config_tool)

        data_target_config = self.data_target
        return config_tool, data_target_config

    def process(
        self, dict_args, secret_tool, config_tool
    ) -> "Tuple[List, InputCore]":
        init_config_tool = self.devops_platform_gateway.get_remote_config(
            dict_args["remote_config_repo"], "engine_dast/ConfigTool.json"
        )

        exclusions = self.devops_platform_gateway.get_remote_config(
            dict_args["remote_config_repo"],
            "engine_dast/Exclusions.json"
        )

        config_tool, data_target = self.complete_config_tool(
            data_file_tool=init_config_tool,
            exclusions=exclusions,
            tool=config_tool["TOOL"],
        )

        finding_list, path_file_results = self.tool_gateway.run_tool(
            target_data=data_target,
            config_tool=config_tool,
            secret_tool=secret_tool,
            secret_external_checks=dict_args["token_external_checks"]
        )
        #Here execute other tools and append to finding list
        if len(self.other_tools) > 0:
            for i in range(len(self.other_tools)):
                extra_config_tool, data_target = self.complete_config_tool(
                data_file_tool=init_config_tool,
                exclusions=exclusions,
                tool=self.other_tools[i].TOOL
                )
                extra_finding_list = self.other_tools[i].run_tool(
                    target_data=data_target,
                    config_tool=extra_config_tool
                )
                if len(extra_finding_list) > 0:
                    finding_list.extend(extra_finding_list)

        totalized_exclusions = []
        (
            totalized_exclusions.extend(
                map(
                    lambda elem: Exclusions(**elem), config_tool.exclusions_all
                )
            )
            if config_tool.exclusions_all is not None
            else None
        )
        (
            totalized_exclusions.extend(
                map(
                    lambda elem: Exclusions(**elem),
                    config_tool.exclusions_scope,
                )
            )
            if config_tool.exclusions_scope is not None
            else None
        )

        input_core = InputCore(
            totalized_exclusions=totalized_exclusions,
            threshold_defined=config_tool.threshold,
            path_file_results=path_file_results,
            custom_message_break_build=config_tool.message_info_dast,
            scope_pipeline=config_tool.scope_pipeline,
            stage_pipeline=self.devops_platform_gateway.get_variable("stage"),
        )

        return finding_list, input_core