from abc import ABCMeta, abstractmethod


class RemoteConfigGateway(metaclass=ABCMeta):
    @abstractmethod
    def get_remote_json_config(self, remote_config_repo, remote_config_path_file) -> dict:
        "remote config"
