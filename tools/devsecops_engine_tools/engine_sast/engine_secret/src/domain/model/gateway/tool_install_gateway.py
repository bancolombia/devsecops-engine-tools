from abc import ABCMeta, abstractmethod


class ToolInstallGateway(metaclass=ABCMeta): 
    @abstractmethod
    def check_tool(self) -> str:
        "remote config"
