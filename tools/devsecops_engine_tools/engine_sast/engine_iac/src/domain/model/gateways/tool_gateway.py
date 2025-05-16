from abc import ABCMeta, abstractmethod


class ToolGateway(metaclass=ABCMeta):
    @abstractmethod
    def run_tool(self, config_tool, folders_to_scan, **kwargs):
        "run_tool"

    @abstractmethod
    def get_iac_context_from_results(self, path_file_results) -> None:
        "get_iac_context_from_results"
