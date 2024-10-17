from abc import ABCMeta, abstractmethod
from devsecops_engine_tools.engine_sast.engine_code.src.domain.model.config_tool import (
    ConfigTool,
)

class ToolGateway(metaclass=ABCMeta):

    @abstractmethod
    def run_tool(self, 
                 folder_to_scan: str,
                 pull_request_files: list,
                 agent_work_folder: str,
                 repository: str,
                 config_tool: ConfigTool):
        "run code scan tool"