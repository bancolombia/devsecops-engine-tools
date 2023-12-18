from abc import ABCMeta, abstractmethod


class DevopsPlatformGateway(metaclass=ABCMeta):
    @abstractmethod
    def get_remote_config(self, dict_args):
        "get_remote_config"

    @abstractmethod
    def logging(self, type, message):
        "logging"

    @abstractmethod
    def result_pipeline(self, type):
        "result_pipeline"

    @abstractmethod
    def get_source_code_management_uri(self):
        "get_source_code_management_uri"

    @abstractmethod
    def get_base_compact_remote_config_url(self, remote_config_repo):
        "get_base_compact_remote_config_url"

    @abstractmethod
    def get_variable(self, variable):
        "get_variable"
