from abc import ABCMeta, abstractmethod


class ToolGateway(metaclass=ABCMeta):
    @abstractmethod
    def install_tool(self) -> any:
        "install tool"
    @abstractmethod
    def run_tool_secret_scan(self, system_working_dir: str) -> str:
        "run tool secret scan"
    @abstractmethod
    def decode_output(self) -> str:
        "decode output secret scan"

