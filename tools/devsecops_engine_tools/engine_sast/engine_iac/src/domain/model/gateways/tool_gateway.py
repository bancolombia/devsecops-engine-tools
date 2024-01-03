from abc import ABCMeta, abstractmethod


class ToolGateway(metaclass=ABCMeta):
    @abstractmethod
    def run_tool(self, init_config_tool, exclusions, environment, pipeline, secret_tool) -> str:
        "run_tool"
