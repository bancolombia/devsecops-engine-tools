from abc import ABCMeta, abstractmethod
from devsecops_engine_tools.engine_core.src.domain.model.finding import Finding


class ToolGateway(metaclass=ABCMeta):
    @abstractmethod
    def run_tool(
        self, config_tool, folders_to_scan, environment, secret_tool
    ) -> tuple["list[Finding]", str]:
        "run_tool"
