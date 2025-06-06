from abc import ABCMeta, abstractmethod


class ToolGateway(metaclass=ABCMeta):
    @abstractmethod
    def run_tool_dependencies_sca(
        self, remote_config, dict_args,to_scan, secret_tool, token_engine_dependencies, **kwargs
    ) -> str:
        "run tool dependencies sca"
    
    @abstractmethod
    def get_dependencies_context_from_results(self, path_file_results, **kwargs) -> None:
        "get_dependencies_context_from_results"