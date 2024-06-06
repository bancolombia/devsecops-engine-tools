from dataclasses import dataclass
from devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway import (
    DevopsPlatformGateway,
)
from devsecops_engine_tools.engine_utilities.github.models.GithubPredefinedVariables import (
    BuildVariables,
    SystemVariables,
    ReleaseVariables,
    AgentVariables
)
from devsecops_engine_tools.engine_utilities.github.infrastructure.github_api import (
    GithubApi,
)
import os


@dataclass
class GithubActions(DevopsPlatformGateway):
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    ICON_FAIL = "\u2718"
    ICON_SUCCESS = "\u2714"

    def get_remote_config(self, repository, path):

        owner = SystemVariables.GH_TeamFoundationCollectionUri.value()

        utils_github = GithubApi(
            personal_access_token=SystemVariables.GH_AccessToken.value()
        )

        git_client = utils_github.get_github_connection()
        json_config = utils_github.get_remote_json_config(git_client, owner, repository, path)

        return json_config

    def message(self, type, message):
        formats = {
            "succeeded": f"{self.OKGREEN}{message}{self.ENDC}",
            "info": f"{self.BOLD}{message}{self.ENDC}",
            "warning": f"{self.WARNING}{message}{self.ENDC}",
            "error": f"{self.FAIL}{message}{self.ENDC}"
        }
        return formats.get(type, message)

    def result_pipeline(self, type):
        results = {
            "failed": f"{self.FAIL}{self.ICON_FAIL}Failed{self.ENDC}",
            "succeeded": f"{self.OKGREEN}{self.ICON_SUCCESS}Succeeded{self.ENDC}"
        }
        return results.get(type)

    def get_source_code_management_uri(self):
        return os.environ.get("GH_SOURCE_CODE_MANAGEMENT_URI")

    def get_base_compact_remote_config_url(self, remote_config_repo):
        return os.environ.get("GH_BASE_COMPACT_REMOTE_CONFIG_URL")

    def get_variable(self, variable):
        variable_map = {
            "branch_name": BuildVariables.GH_Build_SourceBranchName,
            "build_id": BuildVariables.GH_Build_BuildNumber,
            "build_execution_id": BuildVariables.GH_Build_BuildId,
            "commit_hash": BuildVariables.GH_Build_SourceVersion,
            "environment": ReleaseVariables.GH_Environment,
            "release_id": ReleaseVariables.GH_Release_Releaseid,
            "branch_tag": BuildVariables.GH_Build_SourceBranch,
            "access_token": SystemVariables.GH_AccessToken,
            "organization": SystemVariables.GH_TeamFoundationCollectionUri,
            "project_name": SystemVariables.GH_TeamProject,
            "repository": BuildVariables.GH_Build_Repository_Name,
            "pipeline_name": (
                BuildVariables.GH_Build_DefinitionName
                if SystemVariables.GH_HostType.value() == "build"
                else ReleaseVariables.GH_Release_Definitionname
            ),
            "stage": SystemVariables.GH_HostType,
            "path_directory": SystemVariables.GH_DefaultWorkingDirectory,
            "os": AgentVariables.GH_Agent_OS,
            "work_folder": AgentVariables.GH_Agent_WorkFolder,
            "temp_directory": AgentVariables.GH_Agent_TempDirectory,
            "agent_directory": AgentVariables.GH_Agent_BuildDirectory,
            "target_branch": SystemVariables.GH_TargetBranchName,
            "source_branch": SystemVariables.GH_SourceBranch,
            "repository_provider": BuildVariables.GH_Build_Repository_Provider,
        }
        try:
            return variable_map.get(variable).value()
        except ValueError:
            return None
