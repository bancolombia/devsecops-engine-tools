from abc import ABCMeta, abstractmethod


class ToolGateway(metaclass=ABCMeta):
    @abstractmethod
    def run_tool(
        self, target_data, config_tool, secret_tool, secret_external_checks, agent_work_folder
    ) -> str:
        "run_tool"
