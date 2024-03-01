from dataclasses import dataclass
from devsecops_engine_tools.engine_sast.engine_secret.src.domain.model.gateway.devops_platform_gateway import (
    DevopsPlatformGateway,
)
from devsecops_engine_utilities.azuredevops.models.AzurePredefinedVariables import (
    AgentVariables,
    SystemVariables,
    BuildVariables,
)
from devsecops_engine_utilities.azuredevops.infrastructure.azure_devops_api import (
    AzureDevopsApi,
)

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
            if variable == "REPOSITORY":
                return BuildVariables.Build_Repository_Name.value()
            elif variable == "PATH_DIRECTORY":
                return SystemVariables.System_DefaultWorkingDirectory.value()
            elif variable == "ACCESS_TOKEN":
                return SystemVariables.System_AccessToken.value()
            elif variable == "ORGANIZATION":
                return SystemVariables.System_TeamFoundationCollectionUri.value()
            elif variable == "PROJECT_ID":
                return SystemVariables.System_TeamProjectId.value()
            elif variable == "PR_ID":
                return SystemVariables.System_PullRequestId.value()
            elif variable == "OS":
                return AgentVariables.Agent_OS.value()
            elif variable == "WORK_FOLDER":
                return AgentVariables.Agent_WorkFolder.value()
            elif variable == "TEMP_DIRECTORY":
                return AgentVariables.Agent_TempDirectory.value()
        except Exception as e:
            print(e)
            return None
