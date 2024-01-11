from abc import ABCMeta, abstractmethod


class ToolGateway(metaclass=ABCMeta):
    @abstractmethod
    def run_tool_container_sca(self, dict_args, token, scan_image) -> str:
        "run tool container sca"
