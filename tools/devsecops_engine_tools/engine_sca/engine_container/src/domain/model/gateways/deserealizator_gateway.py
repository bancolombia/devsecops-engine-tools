from abc import ABCMeta, abstractmethod
from devsecops_engine_tools.engine_core.src.domain.model.finding import Finding
from devsecops_engine_tools.engine_sca.engine_container.src.domain.model.context_container import (
    ContextContainer,
)


class DeseralizatorGateway(metaclass=ABCMeta):
    @abstractmethod
    def get_list_findings(self, results_scan_list: list) -> "list[Finding]":
        "Deseralizator"

    @abstractmethod
    def get_container_context_from_results(
        self, results_scan_list: list
    ) -> "list[ContextContainer]":
        "Deseralizator"
