from abc import ABCMeta, abstractmethod


class SecretsManagerGateway(metaclass=ABCMeta):
    @abstractmethod
    def get_secret(self, config_tool):
        "get_secret"
