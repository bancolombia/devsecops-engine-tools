from abc import ABCMeta, abstractmethod
from devsecops_engine_tools.engine_core.src.domain.model.finding import Finding


class DeseralizatorGateway(metaclass=ABCMeta):
    @abstractmethod
    def get_list_vulnerability(self, results_scan_list: list, path_directory: str, os: str) -> "list[Finding]":
        "Deseralizator"
    @abstractmethod
    def get_where_correctly(self, results_scan_list: any):
        "Transform Where"
