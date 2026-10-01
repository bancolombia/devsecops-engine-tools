from abc import ABCMeta, abstractmethod
from typing import List, TYPE_CHECKING

if TYPE_CHECKING:
    from devsecops_engine_tools.engine_sca.engine_container.src.domain.model.context_container import ContextContainer


class ToolGateway(metaclass=ABCMeta):
    @abstractmethod
    def run_tool_container_sca(self, dict_args, secret_tool, token_engine_container, scan_image, release, base_image, exclusions, generate_sbom, docker_address, is_compressed_file=False, cross_approval_exclusions=None):
        "run tool container sca"

    @abstractmethod
    def get_container_context_from_results(self, path_file_results: str) -> List['ContextContainer']:
        "get_container_context_from_results"
