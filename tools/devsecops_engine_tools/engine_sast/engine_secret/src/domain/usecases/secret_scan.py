from devsecops_engine_tools.engine_core.src.domain.model.input_core import InputCore
from devsecops_engine_tools.engine_sast.engine_secret.src.domain.model.DeserializeConfigTool import (
    DeserializeConfigTool,
)
from devsecops_engine_tools.engine_sast.engine_secret.src.domain.model.gateway.tool_gateway import (
    ToolGateway,
)
from devsecops_engine_tools.engine_sast.engine_secret.src.domain.model.gateway.gateway_deserealizator import (
    DeseralizatorGateway,
)
from devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway import (
    DevopsPlatformGateway,
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
            dict_args["remote_config_repo"], "engine_sast/engine_secret/ConfigTool.json"
        )
        config_tool, skip_tool = self.complete_config_tool(
            init_config_tool, tool
        )
        finding_list = []
        if skip_tool == "false":
            self.tool_gateway.install_tool(self.devops_platform_gateway.get_variable("os"), self.devops_platform_gateway.get_variable("temp_directory"))
            files_pullrequest = self.git_gateway.get_files_pull_request(
                self.devops_platform_gateway.get_variable("work_folder"),
                self.devops_platform_gateway.get_variable("target_branch"),
                config_tool.target_branches,
                self.devops_platform_gateway.get_variable("source_branch"),
                self.devops_platform_gateway.get_variable("access_token"),
                self.devops_platform_gateway.get_variable("organization"),
                self.devops_platform_gateway.get_variable("project_name"),
                self.devops_platform_gateway.get_variable("repository"),
                self.devops_platform_gateway.get_variable("repository_provider"))
            finding_list = self.tool_deserialize.get_list_vulnerability(
                self.tool_gateway.run_tool_secret_scan(
                    files_pullrequest,
                    config_tool.exclude_path,
                    self.devops_platform_gateway.get_variable("os"),
                    self.devops_platform_gateway.get_variable("work_folder"),
                    config_tool.number_threads,
                    self.devops_platform_gateway.get_variable("repository")
                    ),
                self.devops_platform_gateway.get_variable("os"),
                self.devops_platform_gateway.get_variable("work_folder")
                )
        return finding_list, config_tool
    
    def complete_config_tool(self, data_file_tool, tool):
        config_tool = DeserializeConfigTool(json_data=data_file_tool, tool=tool)
        config_tool.scope_pipeline = self.devops_platform_gateway.get_variable("pipeline_name")
        skip_tool = "false"
        if config_tool.scope_pipeline in config_tool.ignore_search_pattern:
            skip_tool = "true"
        return config_tool, skip_tool