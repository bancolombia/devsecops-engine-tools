from abc import ABCMeta, abstractmethod


class ToolGateway(metaclass=ABCMeta):
    @abstractmethod
    def run_tool_function_sca(
        self,
        dict_args,
        token:str=None,
        skip_flag:bool=None,
    ) -> str:
        
        "run tool function sca"
