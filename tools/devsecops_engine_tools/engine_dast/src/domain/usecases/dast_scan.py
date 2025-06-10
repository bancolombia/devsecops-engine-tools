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
from devsecops_engine_tools.engine_core.src.domain.model.threshold import Threshold
from devsecops_engine_tools.engine_utilities.utils.utils import Utils

class DastScan:
    def __init__(
        self,
        tool_gateway: ToolGateway,
        devops_platform_gateway: DevopsPlatformGateway,
        remote_config_source_gateway: DevopsPlatformGateway,
        data_target,
        aditional_tools: "List[ToolGateway]"
    ):
        self.tool_gateway = tool_gateway
        self.devops_platform_gateway = devops_platform_gateway
        self.remote_config_source_gateway = remote_config_source_gateway
        self.data_target = data_target
        self.other_tools = aditional_tools

    def complete_config_tool(
        self, data_file_tool, exclusions, tool
    ) -> "Tuple[Any, Any]":
        
        config_tool = data_file_tool

        config_tool["SCOPE_PIPELINE"] = self.devops_platform_gateway.get_variable(
            "pipeline_name"
        )

        config_tool["EXCLUSIONS"] = exclusions

        config_exclusions = config_tool["EXCLUSIONS"]

        if config_exclusions.get("All") is not None:
            config_tool["EXCLUSIONS_ALL"] = config_exclusions.get("All").get(tool)
        if config_exclusions.get(config_tool["SCOPE_PIPELINE"]) is not None:
            config_tool["EXCLUSIONS_SCOPE"] = config_exclusions.get(
                config_tool["SCOPE_PIPELINE"]
            ).get(tool)

        self.data_target.concurrency = config_tool.get(tool, {}).get("CONCURRENCY", 25)
        self.data_target.response_size = config_tool.get(tool, {}).get("RESPONSE_SIZE", 1048576)
        self.data_target.bulk_size = config_tool.get(tool, {}).get("BULK_SIZE", 25)
        self.data_target.timeout = config_tool.get(tool, {}).get("TIMEOUT", 10)

        data_target_config = self.data_target
        return config_tool, data_target_config

    def process(
        self, dict_args, secret_tool, config_tool
    ) -> "Tuple[List, InputCore]":
        init_config_tool = self.remote_config_source_gateway.get_remote_config(
            dict_args["remote_config_repo"], "engine_dast/ConfigTool.json"
        )

        exclusions = self.remote_config_source_gateway.get_remote_config(
            dict_args["remote_config_repo"],
            "engine_dast/Exclusions.json"
        )

        agent_work_folder = self.devops_platform_gateway.get_variable("path_directory")

        config_tool, data_target = self.complete_config_tool(
            data_file_tool=init_config_tool,
            exclusions=exclusions,
            tool=config_tool["TOOL"],
        )

        finding_list, path_file_results = self.tool_gateway.run_tool(
            target_data=data_target,
            config_tool=config_tool,
            secret_tool=secret_tool,
            secret_external_checks=dict_args["token_external_checks"],
            agent_work_folder=agent_work_folder
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
                    lambda elem: Exclusions(**elem), config_tool.get("EXCLUSIONS_ALL")
                )
            )
            if config_tool.get("EXCLUSIONS_ALL") is not None
            else None
        )
        (
            totalized_exclusions.extend(
                map(
                    lambda elem: Exclusions(**elem),
                    config_tool.get("EXCLUSIONS_SCOPE"),
                )
            )
            if config_tool.get("EXCLUSIONS_SCOPE") is not None
            else None
        )

        input_core = InputCore(
            totalized_exclusions=totalized_exclusions,
            threshold_defined=Utils.update_threshold(
                self,
                Threshold(config_tool['THRESHOLD']),
                exclusions,
                config_tool["SCOPE_PIPELINE"],
            ),
            path_file_results=path_file_results,
            custom_message_break_build=config_tool.get("MESSAGE_INFO_DAST"),
            scope_pipeline=config_tool.get("SCOPE_PIPELINE"),
            scope_service=config_tool.get("SCOPE_PIPELINE"),
            stage_pipeline=self.devops_platform_gateway.get_variable("stage"),
        )

        return finding_list, input_core