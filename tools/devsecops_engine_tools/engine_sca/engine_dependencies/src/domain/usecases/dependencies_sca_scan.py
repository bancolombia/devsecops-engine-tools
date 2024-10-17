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
        dict_args,
        exclusions,
        pipeline_name,
        to_scan,
        secret_tool,
    ):
        self.tool_run = tool_run
        self.tool_deserializator = tool_deserializator
        self.remote_config = remote_config
        self.exclusions = exclusions
        self.pipeline_name = pipeline_name
        self.dict_args = dict_args
        self.to_scan = to_scan
        self.secret_tool = secret_tool

    def process(self):
        """
        Process SCA dependencies scan.

        Return: dict: SCA scanning results.
        """
        return self.tool_run.run_tool_dependencies_sca(
            self.remote_config,
            self.dict_args,
            self.exclusions,
            self.pipeline_name,
            self.to_scan,
            self.secret_tool,
            self.dict_args["token_engine_dependencies"],
        )

    def deserializator(self, dependencies_scanned):
        """
        Process the results deserializer.
        Terun: list: Deserialized list of findings.
        """
        return self.tool_deserializator.get_list_findings(dependencies_scanned)
