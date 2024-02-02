from dataclasses import dataclass
from devsecops_engine_tools.engine_sast.engine_iac.src.domain.model.gateways.devops_platform_gateway import (
    DevopsPlatformGateway,
)
from devsecops_engine_utilities.azuredevops.models.AzurePredefinedVariables import (
    SystemVariables,
    ReleaseVariables,
)
from devsecops_engine_utilities.azuredevops.models.AzureMessageLoggingPipeline import (
    AzureMessageLoggingPipeline,
)
from devsecops_engine_utilities.azuredevops.infrastructure.azure_devops_api import (
    AzureDevopsApi,
)
from devsecops_engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_utilities import settings
logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()

@dataclass
class AzureDevops(DevopsPlatformGateway):
    def get_remote_config(self, remote_config_repo, remote_config_path):
        base_compact_remote_config_url = (
            f"https://{SystemVariables.System_TeamFoundationCollectionUri.value().rstrip('/').split('/')[-1].replace('.visualstudio.com','')}"
            f".visualstudio.com/{SystemVariables.System_TeamProject.value()}/_git/"
            f"{remote_config_repo}?path={remote_config_path}"
        )
        utils_azure = AzureDevopsApi(
            personal_access_token=SystemVariables.System_AccessToken.value(),
            compact_remote_config_url=base_compact_remote_config_url,
        )
        connection = utils_azure.get_azure_connection()
        return utils_azure.get_remote_json_config(connection=connection)

    def get_variable(self, variable):
        try:
            if variable == "pipeline":
                return self.handle_variable()
        except Exception as ex:
            logger.warning(f"Error getting variable {str(ex)}")
            return None

    def handle_variable(self):
        try:
            return ReleaseVariables.Release_Definitionname.value()
        except Exception:
            return SystemVariables.System_TeamProject.value()