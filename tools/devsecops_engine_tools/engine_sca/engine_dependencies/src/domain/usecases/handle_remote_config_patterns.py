import re
import os


class HandleRemoteConfigPatterns:
    def __init__(
        self,
        remote_config,
        exclusions,
        pipeline_name,
    ):
        self.remote_config = remote_config
        self.exclusions = exclusions
        self.pipeline_name = pipeline_name

    def excluded_files(self):
        """
        Handle excluded files.

        Return: string: new regex expresion.
        """

        pattern = self.remote_config["REGEX_EXPRESSION_EXTENSIONS"]
        if (self.pipeline_name in self.exclusions) and (
            self.exclusions[self.pipeline_name].get("SKIP_FILES", 0)
        ):
            exclusion = self.exclusions[self.pipeline_name]["SKIP_FILES"]
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

    def ignore_analysis_pattern(self):
        """
        Handle analysis pattern.

        Return: bool: False -> not scan, True -> scan.
        """
        ignore = self.remote_config["IGNORE_ANALYSIS_PATTERN"]
        if re.match(ignore, self.pipeline_name, re.IGNORECASE):
            return False
        else:
            return True

    def bypass_archive_limits(self):
        """
        Handle bypass archive limits.

        Return: bool: True -> Bypass archive limits, False -> Without bypass archive limits.
        """
        bypass_limits = self.remote_config["BYPASS_ARCHIVE_LIMITS"]
        if re.match(bypass_limits, self.pipeline_name):
            return True
        else:
            return False

    def skip_from_exclusion(self):
        """
        Handle skip tool.

        Return: bool: True -> skip tool, False -> not skip tool.
        """
        if (self.pipeline_name in self.exclusions) and (
            self.exclusions[self.pipeline_name].get("SKIP_TOOL", 0)
        ):
            return True
        else:
            return False
