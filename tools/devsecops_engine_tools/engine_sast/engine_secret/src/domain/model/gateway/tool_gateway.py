from abc import ABCMeta, abstractmethod


class ToolGateway(metaclass=ABCMeta):
    @abstractmethod
    def install_tool(self) -> any:
        "install tool"
    @abstractmethod
    def run_tool_secret_scan(self, system_working_dir: str, exclude_path: dict) -> str:
        "run tool secret scan"

