from abc import ABCMeta, abstractmethod
from devsecops_engine_tools.engine_core.src.domain.model.finding import Finding
from devsecops_engine_tools.engine_sast.engine_secret.src.domain.model.gateway.devops_platform_gateway import (
    DevopsPlatformGateway
)


class DeseralizatorGateway(metaclass=ABCMeta):
    @abstractmethod
    def get_list_vulnerability(self, results_scan_list: list, devops_gateway:DevopsPlatformGateway) -> "list[Finding]":
        "Deseralizator"
    @abstractmethod
    def get_where_correctly(self, results_scan_list: any):
        "Transform Where"
