from abc import ABCMeta, abstractmethod
from devsecops_engine_tools.engine_sast.engine_iac.src.domain.model.LevelCompliance import LevelCompliance



class ConfigGateway(metaclass=ABCMeta):
    @abstractmethod
    def get_list_config(self, results_scan_list: list) -> "list[LevelCompliance]":
        "ConfigGateway"
