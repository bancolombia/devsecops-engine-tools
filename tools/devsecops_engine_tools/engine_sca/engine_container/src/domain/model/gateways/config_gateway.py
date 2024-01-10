from abc import ABCMeta, abstractmethod


class ConfigGateway(metaclass=ABCMeta):
    @abstractmethod
    def get_remote_config(self) -> str:
        "get remote config"
