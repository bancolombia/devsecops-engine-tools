from devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.model.gateways.config_gateway import (
    ConfigGateway,
)


class HandleExcludedFiles:
    def __init__(
        self,
        tool_remote: ConfigGateway,
        dict_args,
    ):
        self.tool_remote = tool_remote
        self.dict_args = dict_args

    def get_remote_config(self, file_path):
        """
        Get remote configuration
        Return: dict: Remote configuration
        """
        return self.tool_remote.get_remote_config(self.dict_args, file_path)

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
            for exclusion in exclusions[pipeline_name]["SKIP_FILES"]:
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

    def process(self):
        """
        Process handle excluded files.

        Return: string: new regex expresion.
        """
        return self.handle_excluded_files(
            self.get_remote_config("SCA/DEPENDENCIES/ConfigTool.json")[
                "REGEX_EXPRESSION_EXTENSIONS"
            ],
            self.get_variable("pipeline_name"),
            self.get_remote_config("SCA/DEPENDENCIES/Exclusions/Exclusions.json"),
        )
