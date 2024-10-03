from abc import ABCMeta, abstractmethod
from devsecops_engine_tools.engine_sast.engine_secret.src.domain.model.DeserializeConfigTool import DeserializeConfigTool

class ToolGateway(metaclass=ABCMeta):
    @abstractmethod
    def install_tool(self, agent_os: str, agent_temp_dir:str) -> any:
        "install tool"
    @abstractmethod
    def run_tool_secret_scan(self,
                            files_pullrequest: dict,
                            agent_os: str,
                            agent_work_folder: str,
                            repository_name: str,
                            config_tool: DeserializeConfigTool,
                            secret_tool,
                            secret_external_checks) -> str:
        "run tool secret scan"