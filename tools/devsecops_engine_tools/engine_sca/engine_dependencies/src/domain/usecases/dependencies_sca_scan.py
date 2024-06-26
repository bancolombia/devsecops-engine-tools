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
        tool_deserializator: DeserializatorGateway,
        remote_config,
        file_to_scan,
        bypass_limits_flag,
        token,
    ):
        self.tool_run = tool_run
        self.tool_deserializator = tool_deserializator
        self.remote_config = remote_config
        self.file_to_scan = file_to_scan
        self.bypass_limits_flag = bypass_limits_flag
        self.token = token

    def process(self):
        """
        Process SCA dependencies scan.

        Return: dict: SCA scanning results.
        """
        return self.tool_run.run_tool_dependencies_sca(
            self.remote_config,
            self.file_to_scan,
            self.bypass_limits_flag,
            self.token,
        )

    def deserializator(self, dependencies_scanned):
        """
        Process the results deserializer.
        Terun: list: Deserialized list of findings.
        """
        return self.tool_deserializator.get_list_findings(dependencies_scanned)
