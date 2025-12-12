from abc import ABCMeta, abstractmethod
from devsecops_engine_tools.engine_core.src.domain.model.finding import Finding


class DeseralizatorGateway(metaclass=ABCMeta):
    @abstractmethod
    def get_list_findings(self, results_scan_list: list) -> "list[Finding]":
        "Deseralizator"
