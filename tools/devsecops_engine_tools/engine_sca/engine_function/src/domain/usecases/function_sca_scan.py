from devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway import (
    DevopsPlatformGateway,
)
from devsecops_engine_tools.engine_sca.engine_function.src.domain.model.gateways.tool_gateway import (
    ToolGateway,
)
from devsecops_engine_tools.engine_sca.engine_function.src.domain.model.gateways.deserealizator_gateway import (
    DeseralizatorGateway,
)


class FunctionScaScan:
    def __init__(
        self,
        tool_run: ToolGateway,
        remote_config,
        tool_remote: DevopsPlatformGateway,
        tool_deseralizator: DeseralizatorGateway,
        dict_args,
        secret_tool,
        token_engine_container
    ):
        self.tool_run = tool_run
        self.remote_config = remote_config
        self.tool_remote = tool_remote
        self.tool_deseralizator = tool_deseralizator
        self.dict_args = dict_args
        self.secret_tool = secret_tool
        self.token_engine_container = token_engine_container

    def get_remote_config(self, file_path):
        """
        Get remote configuration.

        Returns:
            dict: Remote configuration.
        """
        return self.tool_remote.get_remote_config(self.dict_args["remote_config_repo"], file_path, self.dict_args["remote_config_branch"])


    def get_variable(self, variable):
        """
        Get variable.

        Returns:
            dict: Remote variable.
        """
        return self.tool_remote.get_variable(variable)

    def process(self):
        """
        Process SCA scanning.

        Returns:
            dict: SCA scanning results.
        """

        return self.tool_run.run_tool_function_sca(
            self.get_remote_config("engine_sca/engine_function/ConfigTool.json"),
            self.secret_tool,
            self.token_engine_container,
        )

    def deseralizator(self, function_scanned):
        """
        Process the results deserializer.

        Returns:
            list: Deserialized list of findings.
        """
        return self.tool_deseralizator.get_list_findings(function_scanned)
