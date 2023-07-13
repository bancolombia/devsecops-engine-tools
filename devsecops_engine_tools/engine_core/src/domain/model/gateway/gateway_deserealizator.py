from abc import ABCMeta, abstractmethod
from engine_core.src.domain.model.Vulnerability import Vulnerability


class DeseralizatorGateway(metaclass=ABCMeta):
    @abstractmethod
    def get_list_vulnerability(self) -> list[Vulnerability]:
        "Deseralizator"
