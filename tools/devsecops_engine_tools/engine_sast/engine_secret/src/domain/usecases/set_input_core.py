from devsecops_engine_tools.engine_core.src.domain.model.input_core import InputCore
from devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway import (
    DevopsPlatformGateway,
)
from devsecops_engine_tools.engine_sast.engine_secret.src.domain.model.DeserializeConfigTool import (
    DeserializeConfigTool
    )
from devsecops_engine_tools.engine_core.src.domain.model.exclusions import Exclusions


class SetInputCore:
    def __init__(self, tool_remote: DevopsPlatformGateway, dict_args, tool, config_tool: DeserializeConfigTool):
        self.tool_remote = tool_remote
        self.dict_args = dict_args
        self.tool = tool
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
                            create_date=item.get("create_date", ""),
                            expired_date=item.get("expired_date", ""),
                            severity=item.get("severity", ""),
                            hu=item.get("hu", ""),
                            reason=item.get("reason", "Risk acceptance"),
                        )
                        for item in value[tool]
                    ]
                    list_exclusions.extend(exclusions)
        return list_exclusions

    def set_input_core(self, finding_list):
        """
        Set the input core.

        Returns:
            dict: Input core.
        """
        return InputCore(
            totalized_exclusions=self.get_exclusions(
                self.get_remote_config("engine_sast/engine_secret/Exclusions.json"),
                self.get_variable("pipeline_name"),
                self.tool,
            ),
            threshold_defined=self.config_tool.level_compliance,
            path_file_results=finding_list,
            custom_message_break_build=self.config_tool.message_info_engine_secret,
            scope_pipeline=self.config_tool.scope_pipeline,
            stage_pipeline=self.tool_remote.get_variable("stage").capitalize()
        )
