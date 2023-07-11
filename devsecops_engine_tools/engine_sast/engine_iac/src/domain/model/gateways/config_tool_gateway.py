from abc import ABCMeta, abstractmethod
import json


class ConfigToolGateway(metaclass=ABCMeta):
    @abstractmethod
    def create_config_dict(self) -> json:
        "remote config"
