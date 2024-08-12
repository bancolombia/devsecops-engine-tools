from abc import ABCMeta, abstractmethod

class ToolGateway(metaclass=ABCMeta):
    @abstractmethod
    def run_tool(self, config_tool, folders_to_scan, **kwargs):
        "run_tool"
