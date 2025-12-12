from devsecops_engine_tools.engine_core.src.domain.model.input_core import InputCore
from devsecops_engine_tools.engine_core.src.domain.model.threshold import Threshold
from devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway import (
    DevopsPlatformGateway,
)
from devsecops_engine_tools.engine_core.src.domain.model.exclusions import Exclusions


class SetInputCore:
    def __init__(self, tool_remote: DevopsPlatformGateway, dict_args, config_tool):
        self.tool_remote = tool_remote
        self.dict_args = dict_args
        self.config_tool = config_tool

    def get_remote_config(self, file_path):
        """
        Get remote configuration.

        Returns:
            dict: Remote configuration.
        """
        return self.tool_remote.get_remote_config(self.dict_args["remote_config_repo"], file_path)

    def get_variable(self, variable):
        """
        Get variable.

        Returns:
            dict: Remote variable.
        """
        return self.tool_remote.get_variable(variable)

    def get_exclusions(self, exclusions_data, pipeline_name, tool):
        list_exclusions = []
        for key, value in exclusions_data.items():
            if (key == "All") or (key == pipeline_name):
                if value.get(tool, 0):
                    exclusions = [
                        Exclusions(
                            id=item.get("id", ""),
                            where=item.get("where", ""),
                            cve_id=item.get("cve_id", ""),
                            create_date=item.get("create_date", ""),
                            expired_date=item.get("expired_date", ""),
                            severity=item.get("severity", ""),
                            hu=item.get("hu", ""),
                            reason=item.get("reason", "DevSecOps policy"),
                        )
                        for item in value[tool]
                    ]
                    list_exclusions.extend(exclusions)
        return list_exclusions

    def set_input_core(self):
        """
        Set the input core.

        Returns:
            dict: Input core.
        """        
        path_file_results = self.dict_args.get("path_file_results")
        return InputCore(
            self.get_exclusions(
                self.get_remote_config("engine_sca/engine_function/Exclusions.json"),
                self.get_variable("pipeline_name"),
                self.config_tool["TOOL"],
            ),
            Threshold(
                self.get_remote_config("engine_sca/engine_function/ConfigTool.json")["THRESHOLD"]
            ),
            path_file_results,
            self.get_remote_config("engine_sca/engine_function/ConfigTool.json")["MESSAGE_INFO_ENGINE_FUNCTION"],
            self.get_variable("pipeline_name"),
            self.get_variable("pipeline_name"),
            self.get_variable("stage"),
        )
