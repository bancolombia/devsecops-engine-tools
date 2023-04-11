from abc import ABCMeta, abstractmethod


class ToolGateway(metaclass=ABCMeta):
    @abstractmethod
    def run_tool(self, path_config_file) -> str:
        "remote config"
