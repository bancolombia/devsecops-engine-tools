from abc import ABCMeta, abstractmethod
from typing import List, TYPE_CHECKING

if TYPE_CHECKING:
    from devsecops_engine_tools.engine_sast.engine_scripts.src.domain.model.context_script import ContextScript


class ToolGateway(metaclass=ABCMeta):
    @abstractmethod
    def run_tool(self, config_tool, folders_to_scan, **kwargs):
        raise NotImplementedError

    @abstractmethod
    def get_scripts_context_from_results(self, path_file_results) -> List['ContextScript']:
        raise NotImplementedError
