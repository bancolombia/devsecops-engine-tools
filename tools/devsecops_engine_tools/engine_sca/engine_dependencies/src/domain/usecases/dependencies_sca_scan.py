from devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.model.gateways.config_gateway import (
    ConfigGateway,
)
from devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.model.gateways.tool_gateway import (
    ToolGateway,
)
from devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.model.gateways.deserializator_gateway import (
    DeserializatorGateway,
)

class DependenciesScan:
    def __init__(
        self,
        tool_run: ToolGateway,
        tool_remote: ConfigGateway,
        tool_deserializator: DeserializatorGateway,
        dict_args,
        token,
    ):
        self.tool_run = tool_run
        self.tool_remote = tool_remote
        self.tool_deserializator = tool_deserializator
        self.dict_args = dict_args
        self.token = token

    def get_remote_config(self):
        """
        Get remote configuration
        Return: dict: Remote configuration
        """
        return self.tool_remote.get_remote_config(self.dict_args)

    def process(self):
        """
        Process SCA dependencies scan.

        Return: dict: SCA scanning results.
        """
        return self.tool_run.run_tool_dependencies_sca(self.get_remote_config(), self.token)

    def deserializator(self, dependencies_scanned):
        """
        Process the results deserializer.
        Terun: list: Deserialized list of findings.
        """
        return self.tool_deserializator.get_list_findings(dependencies_scanned)
