from devsecops_engine_tools.engine_core.src.domain.model.input_core import InputCore
from devsecops_engine_tools.engine_sca.engine_container.src.domain.model.LevelCompliance import LevelCompliance
from devsecops_engine_tools.engine_sca.engine_container.src.domain.model.gateways.config_gateway import ConfigGateway
import os

class SetInputCore():

    def __init__(self, tool_remote:ConfigGateway, dict_args):
        self.tool_remote = tool_remote
        self.dict_args  = dict_args

        
    def getRemoteConfig(self):
        """
        Get remote configuration.
        
        Returns:
            dict: Remote configuration.
        """
        return self.tool_remote.get_remote_config(self.dict_args)
    
    
    def setInputCore(self,images_scanned):
        """
        Set the input core.
        
        Returns:
            dict: Input core.
        """
        return InputCore(
            [],
            LevelCompliance(self.getRemoteConfig()['PRISMA_CLOUD']['LEVEL_COMPLIANCE'][self.dict_args['environment']]),
            images_scanned[-1],
            "Please refer to documentation for more information",
            os.environ.get("BUILD_DEFINITIONNAME", "")
        )