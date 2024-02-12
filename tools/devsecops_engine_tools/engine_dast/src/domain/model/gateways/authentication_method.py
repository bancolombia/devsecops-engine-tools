from abc import ABCMeta, abstractmethod


class AuthenticationGateway(metaclass=ABCMeta):
    @abstractmethod
    def get_credentials(self, target_data) -> dict:
        "get_credentials"
