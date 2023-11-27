from abc import ABCMeta, abstractmethod


class SecretsManagerGateway(metaclass=ABCMeta):
    @abstractmethod
    def get_secret(self, dict_args):
        "get_secret"
