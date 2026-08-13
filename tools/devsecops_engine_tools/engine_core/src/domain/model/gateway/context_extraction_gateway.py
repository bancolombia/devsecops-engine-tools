from abc import ABCMeta, abstractmethod
from typing import Optional, Dict, Any


class ContextExtractionGateway(metaclass=ABCMeta):

    @abstractmethod
    def extract_context(
        self,
        module_name: str,
        path_file_results: Optional[str],
        remote_config: Dict[str, Any],
        print_to_logs: bool = False,
        **kwargs
    ) -> None:
        pass
