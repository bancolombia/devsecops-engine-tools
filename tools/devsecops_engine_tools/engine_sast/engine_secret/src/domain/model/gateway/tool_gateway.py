from abc import ABCMeta, abstractmethod

class ToolGateway(metaclass=ABCMeta):
    @abstractmethod
    def install_tool(self, agent_os: str, agent_temp_dir:str, version: str) -> any:
        "install tool"
    @abstractmethod
    def run_tool_secret_scan(self,
                            files_pullrequest: dict,
                            agent_os: str,
                            agent_work_folder: str,
                            repository_name: str,
                            config_tool,
                            secret_tool,
                            secret_external_checks,
                            agent_tem_dir:str,
                            tool,
                            folder_path) -> str:
        "run tool secret scan"