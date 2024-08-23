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
from devsecops_engine_tools.engine_utilities.git_cli.model.gateway.git_gateway import (
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

    def process(self, skip_tool, config_tool):
        finding_list = []
        file_path_findings = ""
        if skip_tool == False:
            self.tool_gateway.install_tool(self.devops_platform_gateway.get_variable("os"), self.devops_platform_gateway.get_variable("temp_directory"))
            files_pullrequest = self.git_gateway.get_files_pull_request(
                self.devops_platform_gateway.get_variable("path_directory"),
                self.devops_platform_gateway.get_variable("target_branch"),
                config_tool.target_branches,
                self.devops_platform_gateway.get_variable("source_branch"),
                self.devops_platform_gateway.get_variable("access_token"),
                self.devops_platform_gateway.get_variable("organization"),
                self.devops_platform_gateway.get_variable("project_name"),
                self.devops_platform_gateway.get_variable("repository"),
                self.devops_platform_gateway.get_variable("repository_provider"))
            findings, file_path_findings = self.tool_gateway.run_tool_secret_scan(
                    files_pullrequest,
                    config_tool.exclude_path,
                    self.devops_platform_gateway.get_variable("os"),
                    self.devops_platform_gateway.get_variable("path_directory"),
                    config_tool.number_threads,
                    self.devops_platform_gateway.get_variable("repository")
                    )
            finding_list = self.tool_deserialize.get_list_vulnerability(
                findings,
                self.devops_platform_gateway.get_variable("os"),
                self.devops_platform_gateway.get_variable("path_directory")
                )
        return finding_list, file_path_findings
    
    def complete_config_tool(self, dict_args, tool):
        tool = str(tool).lower()
        init_config_tool = self.devops_platform_gateway.get_remote_config(
            dict_args["remote_config_repo"], "engine_sast/engine_secret/ConfigTool.json"
        )
        config_tool = DeserializeConfigTool(json_data=init_config_tool, tool=tool)
        config_tool.scope_pipeline = self.devops_platform_gateway.get_variable("pipeline_name")
        return config_tool
        
    def skip_from_exclusion(self, exclusions):
        """
        Handle skip tool.

        Return: bool: True -> skip tool, False -> not skip tool.
        """
        pipeline_name = self.devops_platform_gateway.get_variable("pipeline_name")
        if (pipeline_name in exclusions) and (
            exclusions[pipeline_name].get("SKIP_TOOL", 0)
        ):
            return True
        else:
            return False