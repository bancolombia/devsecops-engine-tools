from abc import ABCMeta, abstractmethod


class ToolGateway(metaclass=ABCMeta):
    @abstractmethod
    def install_tool(self, agent_os: str, agent_temp_dir:str) -> any:
        "install tool"
    @abstractmethod
    def run_tool_secret_scan(self,
                            files_pullrequest: dict,
                            exclude_path: dict,
                            agent_os: str,
                            agent_work_folder: str,
                            sys_working_dir: str,
                            num_threads: int) -> str:
        "run tool secret scan"