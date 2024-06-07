from abc import ABCMeta, abstractmethod


class ToolGateway(metaclass=ABCMeta):
    @abstractmethod
    def run_tool_dependencies_sca(
        self, remote_config, file_to_scan, bypass_limits_flag, token
    ) -> str:
        "run tool dependencies sca"
