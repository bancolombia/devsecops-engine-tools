from devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway import (
    DevopsPlatformGateway,
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
        tool_remote: DevopsPlatformGateway,
        tool_deserializator: DeserializatorGateway,
        dict_args,
        working_dir,
        skip_flag,
        scan_flag,
        bypass_limits_flag,
        pattern,
        token,
    ):
        self.tool_run = tool_run
        self.tool_remote = tool_remote
        self.tool_deserializator = tool_deserializator
        self.dict_args = dict_args
        self.working_dir = working_dir
        self.skip_flag = skip_flag
        self.scan_flag = scan_flag
        self.bypass_limits_flag = bypass_limits_flag
        self.pattern = pattern
        self.token = token

    def get_remote_config(self, file_path):
        """
        Get remote configuration
        Return: dict: Remote configuration
        """
        return self.tool_remote.get_remote_config(
            self.dict_args["remote_config_repo"], file_path
        )

    def process(self):
        """
        Process SCA dependencies scan.

        Return: dict: SCA scanning results.
        """
        return self.tool_run.run_tool_dependencies_sca(
            self.get_remote_config("engine_sca/engine_dependencies/ConfigTool.json"),
            self.working_dir,
            self.skip_flag,
            self.scan_flag,
            self.bypass_limits_flag,
            self.pattern,
            self.token,
        )

    def deserializator(self, dependencies_scanned):
        """
        Process the results deserializer.
        Terun: list: Deserialized list of findings.
        """
        return self.tool_deserializator.get_list_findings(dependencies_scanned)
