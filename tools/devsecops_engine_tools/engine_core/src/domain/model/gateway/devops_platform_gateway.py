from abc import ABCMeta, abstractmethod


class DevopsPlatformGateway(metaclass=ABCMeta):
    @abstractmethod
    def get_remote_config(self, dict_args):
        "get_remote_config"
