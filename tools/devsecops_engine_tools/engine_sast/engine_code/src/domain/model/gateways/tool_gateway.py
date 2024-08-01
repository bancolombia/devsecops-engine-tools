from abc import ABCMeta, abstractmethod

class ToolGateway(metaclass=ABCMeta):
    @abstractmethod
    def install_tool(self, 
                     agent_work_folder: str):
        "install code scan tool"

    @abstractmethod
    def run_tool(self, 
                 folder_to_scan: str,
                 pull_request_files: list,
                 agent_work_folder: str,
                 repository: str,
                 list_exclusions: list):
        "run code scan tool"