from abc import ABCMeta, abstractmethod
from devsecops_engine_tools.engine_core.src.domain.model.vulnerability import (
    Vulnerability,
)

class PrintTableGateway(metaclass=ABCMeta):
    @abstractmethod
    def print_table(self, vulnerability_list: "list[Vulnerability]"):
        "print_table"