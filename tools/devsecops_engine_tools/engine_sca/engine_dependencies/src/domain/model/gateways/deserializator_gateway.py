from abc import ABCMeta, abstractmethod
from devsecops_engine_tools.engine_core.src.domain.model.finding import Finding
from devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.model.context_dependencies import ContextDependencies


class DeserializatorGateway(metaclass=ABCMeta):
    @abstractmethod
    def get_list_findings(self, results_scan_file, remote_config) -> "list[Finding]":
        "Deserializator"

    def get_dependencies_context_from_results(self, results_scan_file) -> "list[ContextDependencies]":
        "Deseralizator"

