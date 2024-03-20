import re
import os


class HandleRemoteConfigPatterns:
    def __init__(
        self,
        remote_config,
        exclusions,
        pipeline_name,
        agent_directory,
    ):
        self.remote_config = remote_config
        self.exclusions = exclusions
        self.pipeline_name = pipeline_name
        self.agent_directory = agent_directory

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
            self.remote_config["REGEX_EXPRESSION_EXTENSIONS"],
            self.pipeline_name,
            self.exclusions,
        )

    def handle_analysis_pattern(self, ignore, pipeline_name):
        """
        Handle analysis pattern.

        Return: bool: False -> not scan, True -> scan.
        """
        if re.match(ignore, pipeline_name, re.IGNORECASE):
            return False
        else:
            return True

    def process_handle_analysis_pattern(self):
        """
        Process analysis pattern.

        Return: bool: False -> not scan, True -> scan.
        """
        return self.handle_analysis_pattern(
            self.remote_config["IGNORE_ANALYSIS_PATTERN"],
            self.pipeline_name,
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
            self.remote_config["BYPASS_ARCHIVE_LIMITS"],
            self.pipeline_name,
        )

    def handle_skip_tool(self, exclusions, pipeline_name):
        """
        Handle skip tool.

        Return: bool: True -> skip tool, False -> not skip tool.
        """
        if (pipeline_name in exclusions) and (
            exclusions[pipeline_name].get("SKIP_TOOL", 0)
        ):
            return True
        else:
            return False

    def process_handle_skip_tool(self):
        """
        Process handle skip tool.

        Return: bool: True -> skip tool, False -> not skip tool.
        """
        return self.handle_skip_tool(
            self.exclusions,
            self.pipeline_name,
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
            self.remote_config["WORK_DIR_DIFFERENT_FLAG"],
            self.agent_directory,
        )
