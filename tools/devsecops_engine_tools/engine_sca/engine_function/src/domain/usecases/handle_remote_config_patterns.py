import re

class HandleRemoteConfigPatterns:
    def __init__(self, remote_config, exclusions, pipeline_name):
        self.remote_config = remote_config
        self.exclusions = exclusions
        self.pipeline_name = pipeline_name

    def get_remote_config(self, file_path):
        """
        Get remote configuration
        Return: dict: Remote configuration
        """
        return self.tool_remote.get_remote_config(
            self.dict_args["remote_config_repo"], file_path, self.dict_args["remote_config_branch"]
        )

    def get_variable(self, variable):
        """
        Get variable.

        Returns:
            dict: Remote variable.
        """
        return self.tool_remote.get_variable(variable)
    
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
            self.get_remote_config("engine_sca/engine_function/Exclusions.json"),
            self.get_variable("pipeline_name"),
        )
    
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
