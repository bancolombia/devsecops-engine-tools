import unittest
from unittest.mock import MagicMock
from unittest import mock
from devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.github.github_actions import GithubActions


class TestGithubActions(unittest.TestCase):

    @mock.patch(
        'devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.github.github_actions.GithubApi',
        autospec=True
    )
    @mock.patch(
        'devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.github.github_actions.SystemVariables',
        autospec=True
    )
    def test_get_remote_config(self, mock_system_variables, mock_github_api):
        github_actions = GithubActions()

        # Set up mock values for SystemVariables
        mock_system_variables.github_repository.value.return_value = "github_repository"

        # Mock the AzureDevopsApi class
        mock_github_api_instance = MagicMock()
        mock_github_api_instance.get_azure_connection.return_value = "MockedConnection"
        mock_github_api_instance.get_remote_json_config.return_value = {'key': 'value'}
        mock_github_api.return_value = mock_github_api_instance

        remote_config_repo = "my_repo"
        remote_config_path = "my_path"
        result = github_actions.get_remote_config(remote_config_repo, remote_config_path)

        assert result == {"key": "value"}

    def test_message(self):

        github_actions = GithubActions()

        assert github_actions.message("succeeded", "message") == "::group::message"
        assert github_actions.message("info", "message") == "::notice::message"
        assert github_actions.message("warning", "message") == "::warning::message"
        assert github_actions.message("error", "message") == "::error::message"

    def test_result_pipeline(self):
        ENDC = "\033[0m"
        FAIL = "\033[91m"
        OKGREEN = "\033[92m"
        ICON_FAIL = "\u2718"
        ICON_SUCCESS = "\u2714"

        github_actions = GithubActions()

        assert github_actions.result_pipeline("failed") == f"{FAIL}{ICON_FAIL}Failed{ENDC}"
        assert github_actions.result_pipeline("succeeded") == f"{OKGREEN}{ICON_SUCCESS}Succeeded{ENDC}"

    @mock.patch(
        'devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.github.github_actions.SystemVariables',
        autospec=True)
    @mock.patch(
        'devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.github.github_actions.BuildVariables',
        autospec=True)
    @mock.patch(
        'devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.github.github_actions.ReleaseVariables',
        autospec=True)
    def test_get_variable(self, mock_release_variables, mock_build_variables, mock_system_variables):
        github_actions = GithubActions()

        # Mock the BuildVariables class
        mock_build_variables.github_ref.value.return_value = "github_ref"
        mock_build_variables.github_run_number.value.return_value = "github_run_number"
        mock_build_variables.github_run_id.value.return_value = "github_run_id"
        mock_build_variables.github_sha.value.return_value = "github_sha"
        

        # Mock the ReleaseVariables class
        mock_release_variables.github_workflow.value.return_value = "github_workflow"
        mock_release_variables.github_env.value.return_value = "github_env"
        mock_release_variables.github_run_number.value.return_value = "github_run_number"

        # Mock the SystemVariables class
        mock_system_variables.github_access_token.value.return_value = "github_access_token"

        result = github_actions.get_variable("branch_name")
        assert result == "github_ref"

        result = github_actions.get_variable("build_id")
        assert result == "github_run_number"

        result = github_actions.get_variable("build_execution_id")
        assert result == "github_run_id"

        result = github_actions.get_variable("commit_hash")
        assert result == "github_sha"

        result = github_actions.get_variable("environment")
        assert result == "github_env"

        result = github_actions.get_variable("release_id")
        assert result == "github_run_number"

        result = github_actions.get_variable("branch_tag")
        assert result == "github_ref"

        result = github_actions.get_variable("access_token")
        assert result == "github_access_token"
