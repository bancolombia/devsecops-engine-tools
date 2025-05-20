from devsecops_engine_tools.engine_core.src.domain.model.input_core import InputCore
from devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway import (
    DevopsPlatformGateway,
)
from devsecops_engine_tools.engine_core.src.domain.model.exclusions import Exclusions
from devsecops_engine_tools.engine_utilities.utils.utils import Utils
from devsecops_engine_tools.engine_core.src.domain.model.threshold import Threshold

class SetInputCore:
    def __init__(
        self,
        tool_remote: DevopsPlatformGateway,
        remote_config_source_gateway: DevopsPlatformGateway,
        dict_args,
        tool,
        config_tool,
    ):
        self.tool_remote = tool_remote
        self.remote_config_source_gateway = remote_config_source_gateway
        self.dict_args = dict_args
        self.tool = tool
        self.config_tool = config_tool

    def get_remote_config(self, file_path):
        """
        Get remote configuration.

        Returns:
            dict: Remote configuration.
        """
        return self.remote_config_source_gateway.get_remote_config(
            self.dict_args["remote_config_repo"], file_path, self.dict_args["remote_config_branch"]
        )

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
                            reason=item.get("reason", "DevSecOps policy"),
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
        exclusions_config = self.get_remote_config(
            "engine_sast/engine_secret/Exclusions.json"
        )
        return InputCore(
            totalized_exclusions=self.get_exclusions(
                exclusions_config,
                self.get_variable("pipeline_name"),
                self.tool,
            ),
            threshold_defined=Utils.update_threshold(
                self,
                Threshold(self.config_tool['THRESHOLD']),
                exclusions_config,
                self.config_tool["SCOPE_PIPELINE"],
            ),
            path_file_results=finding_list,
            custom_message_break_build=self.config_tool["MESSAGE_INFO_ENGINE_SECRET"],
            scope_pipeline=self.config_tool["SCOPE_PIPELINE"],
            scope_service=self.config_tool["SCOPE_PIPELINE"],
            stage_pipeline=self.tool_remote.get_variable("stage").capitalize(),
        )
