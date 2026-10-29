from abc import ABCMeta, abstractmethod
from dataclasses import dataclass, field


@dataclass
class DevopsPlatformGateway(metaclass=ABCMeta):
    exit_code: int = field(default=0, init=False)

    @abstractmethod
    def get_remote_config(self, repository, path, branch):
        "get_remote_config"

    @abstractmethod
    def message(self, type, message):
        "message"

    @abstractmethod
    def result_pipeline(self, type):
        "result_pipeline"

    @abstractmethod
    def get_source_code_management_uri(self):
        "get_source_code_management_uri"

    @abstractmethod
    def get_build_pipeline_execution_url(self):
        "get_build_pipeline_execution_url"

    @abstractmethod
    def get_variable(self, variable):
        "get_variable"

    @abstractmethod
    def set_variable(self, variable, value):
        "set_variable"
