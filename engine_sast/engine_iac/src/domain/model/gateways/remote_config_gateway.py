from abc import ABCMeta, abstractmethod
from requests.models import Response


class RemoteConfigGateway(metaclass=ABCMeta):
    @abstractmethod
    def get_remote_config(self, config_remote) -> Response:
        "remote config"
