import re
from devsecops_engine_tools.engine_sast.engine_code.src.domain.model.gateways.tool_gateway import (
    ToolGateway,
)
from devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway import (
    DevopsPlatformGateway,
)
from devsecops_engine_tools.engine_utilities.git_cli.model.gateway.git_gateway import (
    GitGateway,
)
from devsecops_engine_tools.engine_sast.engine_code.src.domain.model.config_tool import (
    ConfigTool,
)
from devsecops_engine_tools.engine_core.src.domain.model.exclusions import Exclusions
from devsecops_engine_tools.engine_core.src.domain.model.input_core import InputCore
from devsecops_engine_tools.engine_utilities.utils.utils import Utils
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


class CodeScan:
    def __init__(
        self,
        tool_gateway: ToolGateway,
        devops_platform_gateway: DevopsPlatformGateway,
        remote_config_source_gateway: DevopsPlatformGateway,
        git_gateway: GitGateway,
    ):
        self.tool_gateway = tool_gateway
        self.devops_platform_gateway = devops_platform_gateway
        self.remote_config_source_gateway = remote_config_source_gateway
        self.git_gateway = git_gateway

    def set_config_tool(self, dict_args):
        init_config_tool = self.remote_config_source_gateway.get_remote_config(
            dict_args["remote_config_repo"], "engine_sast/engine_code/ConfigTool.json", dict_args["remote_config_branch"]
        )
        scope_pipeline = self.devops_platform_gateway.get_variable("pipeline_name")
        return ConfigTool(json_data=init_config_tool, scope=scope_pipeline)

    def get_pull_request_files(self, target_branches):
        files_pullrequest = self.git_gateway.get_files_pull_request(
            self.devops_platform_gateway.get_variable("path_directory"),
            self.devops_platform_gateway.get_variable("target_branch"),
            target_branches,
            self.devops_platform_gateway.get_variable("source_branch"),
            self.devops_platform_gateway.get_variable("access_token"),
            self.devops_platform_gateway.get_variable("organization"),
            self.devops_platform_gateway.get_variable("project_name"),
            self.devops_platform_gateway.get_variable("repository"),
            self.devops_platform_gateway.get_variable("repository_provider"),
        )
        return files_pullrequest

    def get_exclusions(self, tool, exclusions_data):
        list_exclusions = []
        skip_tool = False
        for pipeline, exclusions in exclusions_data.items():
            if (pipeline == "All") or (
                pipeline == self.devops_platform_gateway.get_variable("pipeline_name")
            ):
                if exclusions.get("SKIP_TOOL", False):
                    skip_tool = True
                elif exclusions.get(tool, False):
                    for exc in exclusions[tool]:
                        exclusion = Exclusions(
                            id=exc.get("id", ""),
                            where=exc.get("where", ""),
                            create_date=exc.get("create_date", ""),
                            expired_date=exc.get("expired_date", ""),
                            severity=exc.get("severity", ""),
                            hu=exc.get("hu", ""),
                            reason=exc.get("reason", "DevSecOps policy"),
                        )
                        list_exclusions.append(exclusion)
        return list_exclusions, skip_tool

    def apply_exclude_path(
        self, exclude_folder, ignore_search_pattern, pull_request_file
    ):
        patterns = ignore_search_pattern
        patterns.extend([rf"/{re.escape(folder)}//*" for folder in exclude_folder])

        for pattern in patterns:
            if re.search(pattern, pull_request_file):
                return True
        return False

    def process(self, dict_args, tool):
        config_tool = self.set_config_tool(dict_args)
        exclusions_data = self.remote_config_source_gateway.get_remote_config(
            dict_args["remote_config_repo"], "engine_sast/engine_code/Exclusions.json"
        )
        list_exclusions, skip_tool = self.get_exclusions(tool, exclusions_data)
        findings_list, path_file_results = [], ""

        if not skip_tool:
            pull_request_files = []
            if not dict_args["folder_path"]:
                pull_request_files = self.get_pull_request_files(
                    config_tool.target_branches
                )
                pull_request_files = [
                    pf
                    for pf in pull_request_files
                    if not self.apply_exclude_path(
                        config_tool.exclude_folder,
                        config_tool.ignore_search_pattern,
                        pf,
                    )
                ]

            findings_list, path_file_results = self.tool_gateway.run_tool(
                dict_args["folder_path"],
                pull_request_files,
                self.devops_platform_gateway.get_variable("path_directory"),
                self.devops_platform_gateway.get_variable("repository"),
                config_tool,
            )

        else:
            print("Tool skipped by DevSecOps policy")
            dict_args["send_metrics"] = "false"
            dict_args["use_vulnerability_management"] = "false"

        input_core = InputCore(
            totalized_exclusions=list_exclusions,
            threshold_defined=Utils.update_threshold(
                self,
                config_tool.threshold,
                exclusions_data,
                config_tool.scope_pipeline,
            ),
            path_file_results=path_file_results,
            custom_message_break_build=config_tool.message_info_engine_code,
            scope_pipeline=config_tool.scope_pipeline,
            scope_service=config_tool.scope_pipeline,
            stage_pipeline=self.devops_platform_gateway.get_variable(
                "stage"
            ).capitalize(),
        )

        return findings_list, input_core
