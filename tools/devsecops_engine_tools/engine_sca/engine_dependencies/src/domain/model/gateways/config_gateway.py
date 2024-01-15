from abc import ABCMeta, abstractmethod


class ConfigGateway(metaclass=ABCMeta):
    @abstractmethod
    def get_remote_config(self, dict_args) -> str:
        "get remote config"

    @abstractmethod
    def get_variable(self, variable) -> str:
        "get variable pipeline"
