from devsecops_engine_tools.engine_sast.engine_iac.src.domain.model.context_iac import ContextIac
from abc import ABCMeta, abstractmethod
import json

class ToolGateway(metaclass=ABCMeta):
    @abstractmethod
    def run_tool(self, config_tool, folders_to_scan, **kwargs):
        "run_tool"

    @classmethod
    def get_iac_context_from_results(
        self, path_file_results
    ) -> None:
        "get_iac_context_from_results"