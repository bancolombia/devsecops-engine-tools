from abc import ABCMeta, abstractmethod

class ToolGateway(metaclass=ABCMeta):
    @abstractmethod
    def install_tool(self, 
                     agent_work_folder: str):
        "install code scan tool"

    @abstractmethod
    def apply_exclude_path(self, 
                 exclude_path: list,
                 pull_request_files: str):
        "apply excluded folders of the pull request files"

    @abstractmethod
    def run_tool(self, 
                 folder_to_scan: str,
                 pull_request_files: list,
                 agent_work_folder: str,
                 repository: str,
                 exclude_path: list):
        "run code scan tool"