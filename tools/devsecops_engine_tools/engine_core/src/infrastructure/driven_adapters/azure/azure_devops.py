from dataclasses import dataclass
from devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway import (
    DevopsPlatformGateway,
)
from devsecops_engine_tools.engine_utilities.azuredevops.models.AzurePredefinedVariables import (
    BuildVariables,
    SystemVariables,
    ReleaseVariables,
    AgentVariables,
    VMVariables,
    CustomVariables,
)
from devsecops_engine_tools.engine_utilities.azuredevops.infrastructure.azure_devops_api import (
    AzureDevopsApi,
)
from devsecops_engine_tools.engine_utilities.azuredevops.models.AzureMessageLoggingPipeline import (
    AzureMessageLoggingPipeline,
    AzureMessageResultPipeline,
)
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


@dataclass
class AzureDevops(DevopsPlatformGateway):
    def get_remote_config(self, repository, path, branch="", **kwargs):
        remote_context = kwargs.get("remote_context") or {}
        organization = remote_context.get("organization") or SystemVariables.System_TeamFoundationCollectionUri.value()
        project = remote_context.get("project") or SystemVariables.System_TeamProject.value()
        pat = remote_context.get("token") or SystemVariables.System_AccessToken.value()

        base_compact_remote_config_url = (
            f"https://{organization.rstrip('/').split('/')[-1].replace('.visualstudio.com','')}"
            f".visualstudio.com/{project}/_git/{repository}?path={path}"
        )

        utils_azure = AzureDevopsApi(
            personal_access_token=pat,
            compact_remote_config_url=base_compact_remote_config_url,
        )
        connection = utils_azure.get_azure_connection()
        return utils_azure.get_remote_json_config(connection=connection, branch=branch)

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
        elif type == "succeeded_with_issues":
            return AzureMessageResultPipeline.SucceededWithIssues.value

    def get_source_code_management_uri(self):
        try:
            repository_variable = self.get_variable("repository")
            source_code_management_uri = {
                "tfsgit": (
                    f"{SystemVariables.System_TeamFoundationCollectionUri.value()}"
                    f"{SystemVariables.System_TeamProject.value()}/_git/{repository_variable}"
                ).replace(" ", "%20"),
                "github": (
                    f"https://github.com/{repository_variable}"
                ),
                "git": (
                    f"{SystemVariables.System_TeamFoundationCollectionUri.value()}"
                    f"{SystemVariables.System_TeamProject.value()}/_git/{repository_variable}"
                ).replace(" ", "%20")
            }
            return source_code_management_uri.get(BuildVariables.Build_Repository_Provider.value().lower())
        except ValueError:
            return None


    def get_build_pipeline_execution_url(self):
        return f"{SystemVariables.System_TeamFoundationCollectionUri.value()}{SystemVariables.System_TeamProject.value()}/_build?buildId={BuildVariables.Build_BuildId.value()}"

    def get_variable(self, variable):

        variable_map = {
            "branch_name": BuildVariables.Build_SourceBranchName,
            "build_id": BuildVariables.Build_BuildNumber,
            "build_execution_id": BuildVariables.Build_BuildId,
            "definition_name": BuildVariables.Build_DefinitionName,
            "commit_hash": BuildVariables.Build_SourceVersion,
            "environment": ReleaseVariables.Environment,
            "release_id": ReleaseVariables.Release_Releaseid,
            "branch_tag": BuildVariables.Build_SourceBranch,
            "access_token": SystemVariables.System_AccessToken,
            "organization": SystemVariables.System_TeamFoundationCollectionUri,
            "project_name": SystemVariables.System_TeamProject,
            "repository": (
                CustomVariables.Repository_Name 
                if CustomVariables.Repository_Name.value() 
                else BuildVariables.Build_Repository_Name
            ),
            "pipeline_name": (
                CustomVariables.Pipeline_Name
                if CustomVariables.Pipeline_Name.value()
                else (
                    BuildVariables.Build_DefinitionName
                    if SystemVariables.System_HostType.value() == "build"
                    else ReleaseVariables.Release_Definitionname
                )
            ),
            "stage": SystemVariables.System_HostType,
            "path_directory": SystemVariables.System_DefaultWorkingDirectory,
            "os": AgentVariables.Agent_OS,
            "temp_directory": AgentVariables.Agent_TempDirectory,
            "target_branch": SystemVariables.System_TargetBranchName,
            "source_branch": SystemVariables.System_SourceBranch,
            "repository_provider": BuildVariables.Build_Repository_Provider,
            "pull_request_id": SystemVariables.System_PullRequestId,
            "vm_product_type_name": VMVariables.Vm_Product_Type_Name,
            "vm_product_name": VMVariables.Vm_Product_Name,
            "vm_product_description": VMVariables.Vm_Product_Description,
            "build_task": CustomVariables.Build_Task,
        }
        try:
            return variable_map.get(variable).value()
        except ValueError:
            return None
        
    def set_variable(self, variable, value):        
        logger.info(f"##vso[task.setvariable variable={variable};]{value}")