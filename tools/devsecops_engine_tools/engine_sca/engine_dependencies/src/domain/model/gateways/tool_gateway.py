from abc import ABCMeta, abstractmethod


class ToolGateway(metaclass=ABCMeta):
    @abstractmethod
    def run_tool_dependencies_sca(
        self, remote_config, dir_to_scan_path, bypass_limits_flag, token
    ) -> str:
        "run tool dependencies sca"
