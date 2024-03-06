from dataclasses import dataclass
from devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway import (
    DevopsPlatformGateway,
)
from devsecops_engine_utilities.azuredevops.models.AzurePredefinedVariables import (
    BuildVariables,
    SystemVariables,
    ReleaseVariables,
    AgentVariables,
)
from devsecops_engine_utilities.azuredevops.infrastructure.azure_devops_api import (
    AzureDevopsApi,
)
from devsecops_engine_utilities.azuredevops.models.AzureMessageLoggingPipeline import (
    AzureMessageLoggingPipeline,
    AzureMessageResultPipeline,
)
from devsecops_engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_utilities import settings
logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


@dataclass
class AzureDevops(DevopsPlatformGateway):
    def get_remote_config(self, repository, path):
        base_compact_remote_config_url = (
            f"https://{SystemVariables.System_TeamFoundationCollectionUri.value().rstrip('/').split('/')[-1].replace('.visualstudio.com','')}"
            f".visualstudio.com/{SystemVariables.System_TeamProject.value()}/_git/"
            f"{repository}?path={path}"
        )
        utils_azure = AzureDevopsApi(
            personal_access_token=SystemVariables.System_AccessToken.value(),
            compact_remote_config_url=base_compact_remote_config_url,
        )
        connection = utils_azure.get_azure_connection()
        return utils_azure.get_remote_json_config(connection=connection)

    def message(self, type, message):
        if type == "succeeded":
            return AzureMessageLoggingPipeline.SucceededLogging.get_message(message)
        elif type == "info":
            return AzureMessageLoggingPipeline.InfoLogging.get_message(message)
        elif type == "warning":
            return AzureMessageLoggingPipeline.WarningLogging.get_message(message)
        elif type == "error":
            return AzureMessageLoggingPipeline.ErrorLogging.get_message(message)

    def result_pipeline(self, type):
        if type == "failed":
            return AzureMessageResultPipeline.Failed.value
        elif type == "succeeded":
            return AzureMessageResultPipeline.Succeeded.value

    def get_source_code_management_uri(self):
        source_code_management_uri = (
            f"{SystemVariables.System_TeamFoundationCollectionUri.value()}"
            f"{SystemVariables.System_TeamProject.value()}/_git/{BuildVariables.Build_Repository_Name.value()}"
        )
        return source_code_management_uri.replace(" ", "%20")

    def get_base_compact_remote_config_url(self, remote_config_repo):
        return (
            f"https://{SystemVariables.System_TeamFoundationCollectionUri.value().rstrip('/').split('/')[-1].replace('.visualstudio.com','')}"
            f".visualstudio.com/{SystemVariables.System_TeamProject.value()}/_git/"
            f"{remote_config_repo}?path=/"
        )

    def get_variable(self, variable):
        try:
            if variable == "branch_name":
                return BuildVariables.Build_SourceBranchName.value()
            elif variable == "build_id":
                return BuildVariables.Build_BuildNumber.value()
            elif variable == "build_execution_id":
                return BuildVariables.Build_BuildId.value()
            elif variable == "commit_hash":
                return BuildVariables.Build_SourceVersion.value()
            elif variable == "environment":
                return ReleaseVariables.Environment.value()
            elif variable == "release_id":
                return ReleaseVariables.Release_Releaseid.value()
            elif variable == "branch_tag":
                return BuildVariables.Build_SourceBranch.value()
            elif variable == "access_token":
                return SystemVariables.System_AccessToken.value()
            elif variable == "pipeline_name":
                return BuildVariables.Build_DefinitionName.value()
            elif variable == "agent_directory":
                return AgentVariables.Agent_BuildDirectory.value()
            elif variable  == "release_name":
                return ReleaseVariables.Release_Definitionname.value()

        except Exception as ex:
            logger.warning(f"Error getting variable {str(ex)}")
            return None
