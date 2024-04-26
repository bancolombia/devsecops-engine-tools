from abc import ABCMeta, abstractmethod
from devsecops_engine_tools.engine_core.src.domain.model.finding import Finding


class DeserializatorGateway(metaclass=ABCMeta):
    @abstractmethod
    def get_list_findings(self, results_scan_file) -> "list[Finding]":
        "Deserializator"
