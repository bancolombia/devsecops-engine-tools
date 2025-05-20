import re

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
        remote_config_source_gateway: DevopsPlatformGateway,
        tool_deserialize: DeseralizatorGateway,
        git_gateway: GitGateway
        ):
        self.tool_gateway = tool_gateway
        self.devops_platform_gateway = devops_platform_gateway
        self.remote_config_source_gateway = remote_config_source_gateway
        self.tool_deserialize = tool_deserialize
        self.git_gateway = git_gateway

    def process(self, skip_tool, config_tool, secret_tool, dict_args, tool):
        tool = str(tool).lower()
        finding_list = []
        file_path_findings = ""
        secret_external_checks=dict_args["token_external_checks"]
        files_to_scan = None if dict_args["folder_path"] is None else [dict_args["folder_path"]]
        if skip_tool == False:
            self.tool_gateway.install_tool(self.devops_platform_gateway.get_variable("os"), self.devops_platform_gateway.get_variable("temp_directory"), config_tool[tool]["VERSION"])
            if files_to_scan is None:
                files_to_scan = self.git_gateway.get_files_pull_request(
                    self.devops_platform_gateway.get_variable("path_directory"),
                    self.devops_platform_gateway.get_variable("target_branch"),
                    config_tool["TARGET_BRANCHES"],
                    self.devops_platform_gateway.get_variable("source_branch"),
                    self.devops_platform_gateway.get_variable("access_token"),
                    self.devops_platform_gateway.get_variable("organization"),
                    self.devops_platform_gateway.get_variable("project_name"),
                    self.devops_platform_gateway.get_variable("repository"),
                    self.devops_platform_gateway.get_variable("repository_provider"))
            findings, file_path_findings = self.tool_gateway.run_tool_secret_scan(
                    files_to_scan,
                    self.devops_platform_gateway.get_variable("os"),
                    self.devops_platform_gateway.get_variable("path_directory"),
                    self.devops_platform_gateway.get_variable("repository"),
                    config_tool,
                    secret_tool,
                    secret_external_checks,
                    self.devops_platform_gateway.get_variable("temp_directory"),
                    tool,
                    dict_args["folder_path"])
            finding_list = self.tool_deserialize.get_list_vulnerability(
                findings,
                self.devops_platform_gateway.get_variable("os"),
                self.devops_platform_gateway.get_variable("path_directory")
                )
        else:
            print("Tool skipped by DevSecOps policy")
            dict_args["send_metrics"] = "false"
            dict_args["use_vulnerability_management"] = "false"
        return finding_list, file_path_findings
    
    def complete_config_tool(self, dict_args, tool):
        tool = str(tool).lower()
        init_config_tool = self.remote_config_source_gateway.get_remote_config(
            dict_args["remote_config_repo"], "engine_sast/engine_secret/ConfigTool.json", dict_args["remote_config_branch"]
        )
        init_config_tool['SCOPE_PIPELINE'] = self.devops_platform_gateway.get_variable("pipeline_name")

        skip_tool = bool(re.match(init_config_tool["IGNORE_SEARCH_PATTERN"], init_config_tool["SCOPE_PIPELINE"], re.IGNORECASE))
        
        return init_config_tool, skip_tool
        
    def skip_from_exclusion(self, exclusions, skip_tool_isp):
        """
        Handle skip tool.

        Return: bool: True -> skip tool, False -> not skip tool.
        """
        if(skip_tool_isp):
            return True
        else:
            pipeline_name = self.devops_platform_gateway.get_variable("pipeline_name")
            if (pipeline_name in exclusions) and (
                exclusions[pipeline_name].get("SKIP_TOOL", 0)
            ):
                return True
            else:
                return False