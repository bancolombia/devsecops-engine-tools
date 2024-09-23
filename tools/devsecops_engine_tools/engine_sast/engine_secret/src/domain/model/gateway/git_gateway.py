from abc import ABCMeta, abstractmethod


class GitGateway(metaclass=ABCMeta):
    @abstractmethod
    def get_files_pull_request(self, sys_working_dir: str,
                               target_branch: str,
                               source_branch: str,
                               message_info_engine_secret: str
                               ) -> dict:
        "get_files_pull_request"
