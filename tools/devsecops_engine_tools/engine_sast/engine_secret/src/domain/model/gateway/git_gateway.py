from abc import ABCMeta, abstractmethod


class GitGateway(metaclass=ABCMeta):
    @abstractmethod
    def get_files_pull_request(self, sys_working_dir: str,
                               target_branch: str,
                               config_target_branch: dict,
                               source_branch: str,
                               access_token: str,
                               collection_uri: str,
                               team_project: str,
                               repository_name: str,
                               repository_provider: str) -> dict:
        "get_files_pull_request"
