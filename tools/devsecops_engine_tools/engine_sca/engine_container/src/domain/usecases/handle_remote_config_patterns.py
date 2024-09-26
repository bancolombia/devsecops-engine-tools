import re


class HandleRemoteConfigPatterns:
    def __init__(self, remote_config, exclusions, pipeline_name):
        self.remote_config = remote_config
        self.exclusions = exclusions
        self.pipeline_name = pipeline_name

    def ignore_analysis_pattern(self):
        """
        Handle analysis pattern.
        Return: bool: False -> not scan, True -> scan.
        """
        ignore = self.remote_config["IGNORE_SEARCH_PATTERN"]
        if re.match(ignore, self.pipeline_name, re.IGNORECASE):
            return False
        else:
            return True

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
