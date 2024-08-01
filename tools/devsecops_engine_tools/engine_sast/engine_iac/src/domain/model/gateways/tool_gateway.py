from abc import ABCMeta, abstractmethod

class ToolGateway(metaclass=ABCMeta):
    @abstractmethod
    def run_tool(self, config_tool, folders_to_scan, environment, platform_to_scan, secret_tool):
        "run_tool"
