from abc import ABCMeta, abstractmethod
from devsecops_engine_tools.engine_core.src.domain.model.finding import (
    Finding,
)

class PrinterTableGateway(metaclass=ABCMeta):
    @abstractmethod
    def print_table(self, finding_list: "list[Finding]"):
        "print_table"