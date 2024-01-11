from devsecops_engine_tools.engine_core.src.domain.model.input_core import InputCore
from devsecops_engine_tools.engine_core.src.domain.model.threshold import Threshold
from devsecops_engine_tools.engine_sca.engine_container.src.domain.model.gateways.config_gateway import (
    ConfigGateway,
)


class SetInputCore:
    def __init__(self, tool_remote: ConfigGateway, dict_args):
        self.tool_remote = tool_remote
        self.dict_args = dict_args

    def get_remote_config(self):
        """
        Get remote configuration.

        Returns:
            dict: Remote configuration.
        """
        return self.tool_remote.get_remote_config(self.dict_args)

    def get_variable(self, variable):
        """
        Get variable.

        Returns:
            dict: Remote variable.
        """
        return self.tool_remote.get_variable(variable)

    def set_input_core(self, images_scanned):
        """
        Set the input core.

        Returns:
            dict: Input core.
        """
        return InputCore(
            [],
            Threshold(self.get_remote_config()["THRESHOLD"]),
            images_scanned[-1] if images_scanned else None,
            self.get_remote_config()["MESSAGE_INFO_SCA_RM"],
            self.get_variable("release_name"),
        )
