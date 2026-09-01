import os
import re
from devsecops_engine_tools.engine_sast.engine_iac.src.domain.model.gateways.tool_gateway import (
    ToolGateway,
)
from devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway import (
    DevopsPlatformGateway,
)
from devsecops_engine_tools.engine_sast.engine_iac.src.domain.model.config_tool import (
    ConfigTool,
)
from devsecops_engine_tools.engine_core.src.domain.model.exclusions import Exclusions
from devsecops_engine_tools.engine_core.src.domain.model.input_core import InputCore
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings
from devsecops_engine_tools.engine_utilities.utils.utils import Utils

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


class IacScan:
    def __init__(
        self, tool_gateway: ToolGateway, devops_platform_gateway: DevopsPlatformGateway, remote_config_source_gateway: DevopsPlatformGateway
    ):
        self.tool_gateway = tool_gateway
        self.devops_platform_gateway = devops_platform_gateway
        self.remote_config_source_gateway = remote_config_source_gateway

    def process(self, dict_args, secret_tool, tool, env):
        config_tool_iac = self.remote_config_source_gateway.get_remote_config(
            dict_args["remote_config_repo"],
            "engine_sast/engine_iac/ConfigTool.json",
            dict_args["remote_config_branch"],
        )

        exclusions = self.remote_config_source_gateway.get_remote_config(
            dict_args["remote_config_repo"],
            "engine_sast/engine_iac/Exclusions.json",
            dict_args["remote_config_branch"],
        )

        config_tool_core, folders_to_scan, skip_tool = self._complete_config_tool(
            config_tool_iac, exclusions, tool, dict_args
        )

        findings_list, path_file_results = [], None
        if skip_tool is False:
            findings_list, path_file_results = self.tool_gateway.run_tool(
                config_tool_iac,
                folders_to_scan,
                environment="pdn" if env not in ["dev", "qa", "pdn"] else env,
                platform_to_scan=dict_args["platform"],
                secret_tool=secret_tool,
                secret_external_checks=dict_args["token_external_checks"],
                work_folder=self.devops_platform_gateway.get_variable("temp_directory"),
                dict_args=dict_args,
            )
        else:
            print("Tool skipped by DevSecOps policy")
            dict_args["send_metrics"] = "false"
            dict_args["use_vulnerability_management"] = "false"

        totalized_exclusions = []
        if config_tool_core.exclusions_all is not None:
            totalized_exclusions.extend(
                [Exclusions(**elem) for elem in config_tool_core.exclusions_all]
            )
        if config_tool_core.exclusions_scope is not None:
            totalized_exclusions.extend(
                [Exclusions(**elem) for elem in config_tool_core.exclusions_scope]
            )

        input_core = InputCore(
            totalized_exclusions=totalized_exclusions,
            threshold_defined=Utils.update_threshold(
                self,
                config_tool_core.threshold,
                exclusions,
                config_tool_core.scope_pipeline,
            ),
            path_file_results=path_file_results,
            custom_message_break_build=config_tool_core.message_info_engine_iac,
            scope_pipeline=config_tool_core.scope_pipeline,
            scope_service=config_tool_core.scope_service,
            stage_pipeline=self.devops_platform_gateway.get_variable(
                "stage"
            ).capitalize(),
        )

        return findings_list, input_core

    def _complete_config_tool(self, data_file_tool, exclusions, tool, dict_args):
        config_tool = ConfigTool(json_data=data_file_tool)

        config_tool.exclusions = exclusions
        config_tool.scope_pipeline = self._resolve_scope_pipeline(data_file_tool)

        skip_tool = bool(
            re.match(
                config_tool.ignore_search_pattern,
                config_tool.scope_pipeline,
                re.IGNORECASE,
            )
        )

        if config_tool.exclusions.get("All") is not None:
            config_tool.exclusions_all = config_tool.exclusions.get("All").get(tool)

        exclusions_scope = self._resolve_exclusions_scope(config_tool)
        if exclusions_scope is not None:
            config_tool.exclusions_scope = exclusions_scope.get(tool)
            skip_tool = bool(exclusions_scope.get("SKIP_TOOL"))

        folders_to_scan = self._resolve_scope_service_and_folders(config_tool, dict_args)

        if len(folders_to_scan) == 0:
            logger.warning(
                "No folders found with the search pattern: %s",
                config_tool.search_pattern,
            )

        return config_tool, folders_to_scan, skip_tool

    def _resolve_scope_pipeline(self, data_file_tool):
        scope_pipeline = self.devops_platform_gateway.get_variable("pipeline_name")
        regex_clean = data_file_tool.get("REGEX_CLEAN_END_PIPELINE_NAME")
        if regex_clean:
            pattern = re.compile(regex_clean)
            match = pattern.match(scope_pipeline)
            if match:
                scope_pipeline = match.group(1)
        return scope_pipeline

    def _resolve_exclusions_scope(self, config_tool):
        exclusions_scope = config_tool.exclusions.get(config_tool.scope_pipeline)
        if exclusions_scope is not None:
            return exclusions_scope

        for pattern, values in config_tool.exclusions.get(
            "BY_PATTERN_SEARCH", {}
        ).items():
            if re.match(pattern, config_tool.scope_pipeline, re.IGNORECASE):
                return values

        return None

    def _resolve_scope_service_and_folders(self, config_tool, dict_args):
        if not dict_args["folder_path"]:
            return self._search_folders(config_tool.search_pattern)

        if (
            config_tool.update_service_file_name_cft
            and "cloudformation" in dict_args["platform"]
        ):
            files = os.listdir(os.path.join(os.getcwd(), dict_args["folder_path"]))
            if len(files) > 0:
                name_file, _ = os.path.splitext(files[0])
                config_tool.scope_service = (
                    f"{config_tool.scope_pipeline}_{name_file}"
                )
        else:
            config_tool.scope_service = config_tool.scope_pipeline

        return [dict_args["folder_path"]]

    def _search_folders(self, search_pattern):
        current_directory = os.getcwd()
        patron = "(?i).*?(" + "|".join(search_pattern) + ").*$"
        folders = [
            folder
            for folder in os.listdir(current_directory)
            if os.path.isdir(os.path.join(current_directory, folder))
        ]
        matching_folders = [
            os.path.normpath(os.path.join(current_directory, folder))
            for folder in folders
            if re.match(patron, folder)
        ]
        return matching_folders
