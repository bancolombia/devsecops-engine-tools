from abc import ABCMeta, abstractmethod


class ToolGateway(metaclass=ABCMeta):
    @abstractmethod
    def run_tool(self) -> str:
        "remote config"

    @abstractmethod
    def create_config_file(self, path_config_file):
        "create_config_file"
