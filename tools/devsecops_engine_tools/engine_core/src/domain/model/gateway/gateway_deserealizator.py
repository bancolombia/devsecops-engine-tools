from abc import ABCMeta, abstractmethod
from devsecops_engine_tools.engine_core.src.domain.model.Vulnerability import Vulnerability


class DeseralizatorGateway(metaclass=ABCMeta):
    @abstractmethod
    def get_list_vulnerability(self, results_scan_list: list) -> "list[Vulnerability]":
        "Deseralizator"
