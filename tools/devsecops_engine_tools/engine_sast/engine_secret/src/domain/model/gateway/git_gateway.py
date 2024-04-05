from abc import ABCMeta, abstractmethod


class GitGateway(metaclass=ABCMeta):
    @abstractmethod
    def get_files_pull_request(self, sys_working_dir: str, target_branch: str, config_target_branch: dict) -> dict:
        "get_files_pull_request"
