from devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway import (
    DevopsPlatformGateway,
)

import re
import os

class HandleRemoteConfigPatterns:
    def __init__(
        self,
        tool_remote: DevopsPlatformGateway,
        dict_args,
    ):
        self.tool_remote = tool_remote
        self.dict_args = dict_args

    def get_remote_config(self, file_path):
        """
        Get remote configuration
        Return: dict: Remote configuration
        """
        return self.tool_remote.get_remote_config(self.dict_args['remote_config_repo'], file_path)

    def get_variable(self, variable):
        """
        Get variable.

        Returns:
            dict: Remote variable.
        """
        return self.tool_remote.get_variable(variable)

    def handle_excluded_files(self, pattern, pipeline_name, exclusions):
        """
        Handle excluded files.

        Return: string: new regex expresion.
        """

        if (pipeline_name in exclusions) and (
            exclusions[pipeline_name].get("SKIP_FILES", 0)
        ):
            exclusion = exclusions[pipeline_name]["SKIP_FILES"]
            if exclusion.get("files", 0):
                excluded_file_types = exclusion["files"]
                pattern2 = pattern
                for ext in excluded_file_types:
                    pattern2 = (
                        pattern2.replace("|" + ext, "")
                        .replace(ext + "|", "")
                        .replace(ext, "")
                    )
                pattern = pattern2

        return pattern

    def process_handle_excluded_files(self):
        """
        Process handle excluded files.

        Return: string: new regex expresion.
        """
        return self.handle_excluded_files(
            self.get_remote_config("SCA/DEPENDENCIES/configTools.json")[
                "REGEX_EXPRESSION_EXTENSIONS"
            ],
            self.get_variable("pipeline_name"),
            self.get_remote_config("SCA/DEPENDENCIES/Exclusions/Exclusions.json"),
        )

    def handle_analysis_pattern(self, ignore, pipeline_name):
        """
        Handle analysis pattern.

        Return: bool: False -> not scan, True -> scan.
        """
        if re.match(ignore, pipeline_name):
            return False
        else:
            return True

    def process_handle_analysis_pattern(self):
        """
        Process analysis pattern.

        Return: bool: False -> not scan, True -> scan.
        """
        return self.handle_analysis_pattern(
            self.get_remote_config("SCA/DEPENDENCIES/configTools.json")[
                "IGNORE_ANALYSIS_PATTERN"
            ],
            self.get_variable("pipeline_name"),
        )

    def handle_bypass_expression(self, bypass_limits, pipeline_name):
        """
        Handle bypass archive limits.

        Return: bool: True -> Bypass archive limits, False -> Without bypass archive limits.
        """
        if re.match(bypass_limits, pipeline_name):
            return True
        else:
            return False
        
    def process_handle_bypass_expression(self):
        """
        Process handle bypass archive limits.

        Return: bool: True -> Bypass archive limits, False -> Without bypass archive limits.
        """
        return self.handle_bypass_expression(
            self.get_remote_config("SCA/DEPENDENCIES/configTools.json")[
                "BYPASS_ARCHIVE_LIMITS"
            ],
            self.get_variable("pipeline_name"),
        )
    
    def handle_skip_tool(self, exclusions, pipeline_name, enabled):
        """
        Handle skip tool.

        Return: bool: True -> skip tool, False -> not skip tool.
        """
        if ((pipeline_name in exclusions) and (exclusions[pipeline_name].get("SKIP_TOOL", 0))) or (enabled.lower() != "true"):
            return True
        else:
            return False
    
    def process_handle_skip_tool(self):
        """
        Process handle skip tool.

        Return: bool: True -> skip tool, False -> not skip tool.
        """
        return self.handle_skip_tool(
            self.get_remote_config("SCA/DEPENDENCIES/Exclusions/Exclusions.json"),
            self.get_variable("pipeline_name"),
            self.get_remote_config("resources/ConfigTool.json")["ENGINE_DEPENDENCIES"]["ENABLED"]
        )

    def handle_working_directory(self, work_dir_different_flag, agent_directory):
        """
        Handle working directory.

        Return: String: Working directory.
        """
        if agent_directory:
            for root, dirs, files in os.walk(agent_directory):
                if work_dir_different_flag in dirs:
                    return agent_directory
        return os.getcwd()

    def process_handle_working_directory(self):
        """
        Process handle working directory.

        Return: String: Working directory.
        """
        return self.handle_working_directory(
            self.get_remote_config("SCA/DEPENDENCIES/configTools.json")["WORK_DIR_DIFFERENT_FLAG"],
            self.get_variable("agent_directory")
        )
