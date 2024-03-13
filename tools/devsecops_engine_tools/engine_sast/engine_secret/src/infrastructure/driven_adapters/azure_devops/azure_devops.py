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
from devsecops_engine_utilities.azuredevops.models.AzureMessageLoggingPipeline import (
    AzureMessageLoggingPipeline,
)
from devsecops_engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_utilities import settings

import requests
import base64

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
    
    def get_pullrequest_iterations(self, repository_name, pr_id):
        try:
            base_compact_pull_request_url = (
                f"https://{SystemVariables.System_TeamFoundationCollectionUri.value().rstrip('/').split('/')[-1].replace('.visualstudio.com','')}"
                f".visualstudio.com/{SystemVariables.System_TeamProject.value()}/_apis/git/repositories/"
                f"{repository_name}/pullRequests/{pr_id}/iterations?api-version=6.0"
            )
            authorization = f":{SystemVariables.System_AccessToken.value()}"
            auth_coded = base64.b64encode(authorization.encode('utf-8')).decode('utf-8')
            headers = {
                'Authorization': f"Basic {auth_coded}"
            }
            results = []
            pr_response = requests.get(base_compact_pull_request_url, headers=headers)
            pr_response.raise_for_status()
            pr_data = pr_response.json()
            commits = pr_data["value"]
            self.get_commits_files(commits, results, repository_name, headers)
            return results
        except requests.RequestException as e:
            e = format(str(e)).replace('apis/', '').replace('/repositories', '').replace('pullRequests', 'pullRequest').replace('/iterations?api-version=6.0', '')
            logger.warning(
                "Error trying to get response from pullrequest: %s",
                e
            )
            return results
    def get_commits_files(self, commits, results, repository_name, headers):
        try:
            for commit in commits:
                num_commit = commit["sourceRefCommit"]["commitId"]
                base_compact_commit_url = (
                f"https://{SystemVariables.System_TeamFoundationCollectionUri.value().rstrip('/').split('/')[-1].replace('.visualstudio.com','')}"
                f".visualstudio.com/{SystemVariables.System_TeamProject.value()}/_apis/git/repositories/"
                f"{repository_name}/commits/{num_commit}/changes?api-version=6.0"
                )
                pr_response_commit = requests.get(base_compact_commit_url, headers=headers)
                pr_response_commit.raise_for_status()
                commit_data = pr_response_commit.json()
                commit_data_list = commit_data["changes"]
                for change in commit_data_list:
                    if change["item"]["gitObjectType"] == "blob":
                        path_changed = SystemVariables.System_DefaultWorkingDirectory.value() + change["item"]["path"]
                        if not path_changed in results:
                            results.append(path_changed)
        except requests.RequestException as e:
            e = format(str(e)).replace('apis/', '').replace('/repositories', '').replace('commits', 'commit').replace('/changes?api-version=6.0', '')
            logger.warning(
                "Error trying to get response from commit: %s",
                e
            )
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
            logger.warning(f"Error getting variable {str(e)}")
            
    def message(self, type, message):
        if type == "succeeded":
            return AzureMessageLoggingPipeline.SucceededLogging.get_message(message)
        elif type == "info":
            return AzureMessageLoggingPipeline.InfoLogging.get_message(message)
        elif type == "warning":
            return AzureMessageLoggingPipeline.WarningLogging.get_message(message)
        elif type == "error":
            return AzureMessageLoggingPipeline.ErrorLogging.get_message(message)