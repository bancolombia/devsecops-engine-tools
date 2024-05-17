from abc import ABCMeta, abstractmethod


class AuthenticationGateway(metaclass=ABCMeta):
    @abstractmethod
    def get_credentials(self) -> dict:
        "get_credentials"
