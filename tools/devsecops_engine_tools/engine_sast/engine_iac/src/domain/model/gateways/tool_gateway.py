from abc import ABCMeta, abstractmethod


class ToolGateway(metaclass=ABCMeta):
    @abstractmethod
    def run_tool(self, data_file_tool, exclusions, environment, pipeline, secret_tool) -> str:
        "run_tool"
