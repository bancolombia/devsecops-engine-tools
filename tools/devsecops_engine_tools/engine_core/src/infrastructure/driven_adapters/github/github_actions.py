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


@dataclass
class GithubActions(DevopsPlatformGateway):
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    ICON_FAIL = "\u2718"
    ICON_SUCCESS = "\u2714"

    def get_remote_config(self, repository, path):

        github_repository = SystemVariables.github_repository.value()
        split = github_repository.split("/")
        owner = split[0]

        utils_github = GithubApi(
            personal_access_token=SystemVariables.github_access_token.value()
        )

        git_client = utils_github.get_github_connection()
        json_config = utils_github.get_remote_json_config(git_client, owner, repository, path)

        return json_config

    def message(self, type, message):
        formats = {
            "succeeded": f"::group::{message}",
            "info": f"::notice::{message}",
            "warning": f"::warning::{message}",
            "error": f"::error::{message}"
        }
        return formats.get(type, message)

    def result_pipeline(self, type):
        results = {
            "failed": f"{self.FAIL}{self.ICON_FAIL}Failed{self.ENDC}",
            "succeeded": f"{self.OKGREEN}{self.ICON_SUCCESS}Succeeded{self.ENDC}",
            "succeeded_with_issues": f"{self.WARNING}{self.ICON_SUCCESS}Succeeded with issues{self.ENDC}"
        }
        return results.get(type)

    def get_source_code_management_uri(self):
        return f"{SystemVariables.github_server_url}/{SystemVariables.github_repository}"

    def get_base_compact_remote_config_url(self, remote_config_repo):
        github_repository = SystemVariables.github_repository.value()
        split = github_repository.split("/")
        owner = split[0]
        return f"{SystemVariables.github_server_url}/{owner}/{remote_config_repo}"

    def get_variable(self, variable):
        variable_map = {
            "branch_name": BuildVariables.github_ref,
            "build_id": BuildVariables.github_run_number,
            "build_execution_id": BuildVariables.github_run_id,
            "commit_hash": BuildVariables.github_sha,
            "environment": ReleaseVariables.github_env,
            "release_id": ReleaseVariables.github_run_number,
            "branch_tag": BuildVariables.github_ref,
            "access_token": SystemVariables.github_access_token,
            "organization": f"{SystemVariables.github_server_url}/{SystemVariables.github_repository}",
            "project_name": SystemVariables.github_repository,
            "repository": BuildVariables.github_repository,
            "pipeline_name": (
                BuildVariables.github_workflow
                if SystemVariables.github_job.value() == "build"
                else ReleaseVariables.github_workflow
            ),
            "stage": SystemVariables.github_job,
            "path_directory": SystemVariables.github_workspace,
            "os": AgentVariables.runner_os,
            "temp_directory": AgentVariables.runner_tool_cache,
            "target_branch": SystemVariables.github_event_base_ref,
            "source_branch": SystemVariables.github_ref,
            "repository_provider": BuildVariables.GitHub,
        }
        try:
            return variable_map.get(variable).value()
        except ValueError:
            return None
