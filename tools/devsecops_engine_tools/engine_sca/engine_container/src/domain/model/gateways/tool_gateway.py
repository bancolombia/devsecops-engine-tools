from abc import ABCMeta, abstractmethod


class ToolGateway(metaclass=ABCMeta):
    @abstractmethod
    def run_tool_container_sca(self, dict_args, secret_tool, token_engine_container, scan_image, release) -> str:
        "run tool container sca"
