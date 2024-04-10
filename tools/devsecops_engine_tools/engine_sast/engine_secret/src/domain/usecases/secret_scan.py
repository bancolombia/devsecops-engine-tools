from devsecops_engine_tools.engine_core.src.domain.model.input_core import InputCore
from devsecops_engine_tools.engine_sast.engine_secret.src.domain.model.DeserializeConfigTool import (
    DeserializeConfigTool
    )
from devsecops_engine_tools.engine_sast.engine_secret.src.domain.model.gateway.tool_gateway import ToolGateway
from devsecops_engine_tools.engine_sast.engine_secret.src.domain.model.gateway.gateway_deserealizator import (
    DeseralizatorGateway
    )
from devsecops_engine_tools.engine_sast.engine_secret.src.domain.model.gateway.devops_platform_gateway import (
    DevopsPlatformGateway
)
from devsecops_engine_tools.engine_sast.engine_secret.src.domain.model.gateway.git_gateway import (
    GitGateway
)

class SecretScan:
    def __init__(
        self,
        tool_gateway: ToolGateway,
        devops_platform_gateway: DevopsPlatformGateway,
        tool_deserialize: DeseralizatorGateway,
        git_gateway: GitGateway
        ):
        self.tool_gateway = tool_gateway
        self.devops_platform_gateway = devops_platform_gateway
        self.tool_deserialize = tool_deserialize
        self.git_gateway = git_gateway

    def process(self, dict_args, tool):
        tool = str(tool).lower()
        init_config_tool = self.devops_platform_gateway.get_remote_config(
            dict_args["remote_config_repo"], "SAST/Secret_Scan/configTools.json"
        )
        config_tool, skip_tool = self.complete_config_tool(
            init_config_tool, tool
        )
        finding_list = []
        if skip_tool == "false":
            self.tool_gateway.install_tool(self.devops_platform_gateway.get_variable("OS"), self.devops_platform_gateway.get_variable("TEMP_DIRECTORY"))
            files_pullrequest = self.git_gateway.get_files_pull_request(self.devops_platform_gateway.get_variable("PATH_DIRECTORY"), self.devops_platform_gateway.get_variable("TARGET_BRANCH"), config_tool.target_branches, self.devops_platform_gateway.get_variable("SOURCE_BRANCH"))
            finding_list = self.tool_deserialize.get_list_vulnerability(
                self.tool_gateway.run_tool_secret_scan(
                    files_pullrequest,
                    config_tool.exclude_path,
                    self.devops_platform_gateway.get_variable("OS"),
                    self.devops_platform_gateway.get_variable("WORK_FOLDER"),
                    self.devops_platform_gateway.get_variable("PATH_DIRECTORY"),
                    config_tool.number_threads,
                    ),
                self.devops_platform_gateway
                )
        input_core = InputCore(
            totalized_exclusions=[],
            threshold_defined=config_tool.level_compliance,
            path_file_results=finding_list,
            custom_message_break_build=config_tool.message_info_sast_build,
            scope_pipeline=config_tool.scope_pipeline,
            stage_pipeline="Build"
        )
        return finding_list, input_core
    def complete_config_tool(self, data_file_tool, tool):
        config_tool = DeserializeConfigTool(json_data=data_file_tool, tool=tool)
        config_tool.scope_pipeline = self.devops_platform_gateway.get_variable("REPOSITORY")
        skip_tool = "false"
        if config_tool.scope_pipeline in config_tool.ignore_search_pattern:
            skip_tool = "true"
        return config_tool, skip_tool