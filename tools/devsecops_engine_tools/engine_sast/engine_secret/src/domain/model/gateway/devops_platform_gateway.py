from abc import ABCMeta, abstractmethod


class DevopsPlatformGateway(metaclass=ABCMeta):
    @abstractmethod
    def get_remote_config(self, remote_config_repo, remote_config_path_file) -> dict:
        "get_remote_config"
        
    @abstractmethod
    def get_pullrequest_iterations(self, repository_name, pr_id) -> dict:
        "get_pullrequest_iterations"

    @abstractmethod
    def get_variable(self, variable):
        "get_variable"
    
    @abstractmethod
    def message(self, type, message):
        "message"
