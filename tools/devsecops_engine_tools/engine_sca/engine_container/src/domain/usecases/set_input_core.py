from devsecops_engine_tools.engine_core.src.domain.model.input_core import InputCore
from devsecops_engine_tools.engine_core.src.domain.model.threshold import Threshold
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
            Threshold(self.getRemoteConfig()['THRESHOLD']),
            images_scanned[-1],
            self.getRemoteConfig()['MESSAGE_INFO_SCA_RM'],
            os.environ.get("BUILD_DEFINITIONNAME", "")
        )