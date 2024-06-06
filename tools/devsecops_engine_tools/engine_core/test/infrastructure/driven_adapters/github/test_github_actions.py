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
        mock_system_variables.GH_TeamFoundationCollectionUri.value.return_value = "GH_TeamFoundationCollectionUri"

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
        OKGREEN = "\033[92m"
        WARNING = "\033[93m"
        FAIL = "\033[91m"
        ENDC = "\033[0m"
        BOLD = "\033[1m"

        github_actions = GithubActions()

        assert github_actions.message("succeeded", "message") == f"{OKGREEN}message{ENDC}"
        assert github_actions.message("info", "message") == f"{BOLD}message{ENDC}"
        assert github_actions.message("warning", "message") == f"{WARNING}message{ENDC}"
        assert github_actions.message("error", "message") == f"{FAIL}message{ENDC}"

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
        azure_devops = GithubActions()

        # Mock the BuildVariables class
        mock_build_variables.GH_Build_SourceBranchName.value.return_value = "GH_Build_SourceBranchName"
        mock_build_variables.GH_Build_BuildNumber.value.return_value = "GH_Build_BuildNumber"
        mock_build_variables.GH_Build_BuildId.value.return_value = "GH_Build_BuildId"
        mock_build_variables.GH_Build_SourceVersion.value.return_value = "GH_Build_SourceVersion"
        mock_build_variables.GH_Build_SourceBranch.value.return_value = "GH_Build_SourceBranch"

        # Mock the ReleaseVariables class
        mock_release_variables.GH_Environment.value.return_value = "GH_Environment"
        mock_release_variables.GH_Release_Releaseid.value.return_value = "GH_Release_Releaseid"

        # Mock the SystemVariables class
        mock_system_variables.GH_AccessToken.value.return_value = "GH_AccessToken"

        result = azure_devops.get_variable("branch_name")
        assert result == "GH_Build_SourceBranchName"

        result = azure_devops.get_variable("build_id")
        assert result == "GH_Build_BuildNumber"

        result = azure_devops.get_variable("build_execution_id")
        assert result == "GH_Build_BuildId"

        result = azure_devops.get_variable("commit_hash")
        assert result == "GH_Build_SourceVersion"

        result = azure_devops.get_variable("environment")
        assert result == "GH_Environment"

        result = azure_devops.get_variable("release_id")
        assert result == "GH_Release_Releaseid"

        result = azure_devops.get_variable("branch_tag")
        assert result == "GH_Build_SourceBranch"

        result = azure_devops.get_variable("access_token")
        assert result == "GH_AccessToken"
