import unittest
from unittest.mock import patch, MagicMock
from unittest import mock

import requests
from devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.azure_devops.azure_devops import (
    AzureDevops,
)


class TestAzureDevops(unittest.TestCase):
    def setUp(self):
        self.azure_devops = AzureDevops()
        
    @mock.patch(
        "devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.azure_devops.azure_devops.AzureDevopsApi",
        autospec=True,
    )
    @mock.patch(
        "devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.azure_devops.azure_devops.SystemVariables",
        autospec=True,
    )
    def test_get_remote_config(self, mock_system_variables, mock_azure_devops_api):
        azure_devops = AzureDevops()

        # Set up mock values for SystemVariables
        mock_system_variables.System_TeamFoundationCollectionUri.value.return_value = (
            "System_TeamFoundationCollectionUri"
        )

        # Mock the AzureDevopsApi class
        mock_azure_devops_api_instance = MagicMock()
        mock_azure_devops_api_instance.get_azure_connection.return_value = (
            "MockedConnection"
        )
        mock_azure_devops_api_instance.get_remote_json_config.return_value = {
            "key": "value"
        }
        mock_azure_devops_api.return_value = mock_azure_devops_api_instance

        remote_config_repo = "my_repo"
        remote_config_path = "my_path"
        result = azure_devops.get_remote_config(remote_config_repo, remote_config_path)

        assert result == {"key": "value"}

    def test_get_variable_build_repository_name(self):
        # Mock the BuildVariables class
        with unittest.mock.patch('devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.azure_devops.azure_devops.BuildVariables') as mock_build_variables:
            mock_build_variables.Build_Repository_Name.value.return_value = "BUILD_REPOSITORY_NAME"

            result = self.azure_devops.get_variable("REPOSITORY")

        self.assertEqual(result, "BUILD_REPOSITORY_NAME")
        
    def test_get_variable_system_default_working_directory(self):
        # Mock the SystemVariables class
        with unittest.mock.patch('devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.azure_devops.azure_devops.SystemVariables') as mock_system_variables:
            mock_system_variables.System_DefaultWorkingDirectory.value.return_value = "SYSTEM_DEFAULTWORKINGDIRECTORY"

            result = self.azure_devops.get_variable("PATH_DIRECTORY")

        self.assertEqual(result, "SYSTEM_DEFAULTWORKINGDIRECTORY")
        
    def test_get_variable_agent_os(self):
        # Mock the SystemVariables class
        with unittest.mock.patch('devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.azure_devops.azure_devops.AgentVariables') as mock_agent_variables:
            mock_agent_variables.Agent_OS.value.return_value = "Linux"

            result = self.azure_devops.get_variable("OS")

        self.assertEqual(result, "Linux")
    
    def test_get_variable_agent_work_folder(self):
        # Mock the SystemVariables class
        with unittest.mock.patch('devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.azure_devops.azure_devops.AgentVariables') as mock_agent_variables:
            mock_agent_variables.Agent_WorkFolder.value.return_value = "/azp/work"

            result = self.azure_devops.get_variable("WORK_FOLDER")

        self.assertEqual(result, "/azp/work")
    
    def test_get_variable_agent_temp_directory(self):
        # Mock the SystemVariables class
        with unittest.mock.patch('devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.azure_devops.azure_devops.AgentVariables') as mock_agent_variables:
            mock_agent_variables.Agent_TempDirectory.value.return_value = "/tmp"

            result = self.azure_devops.get_variable("TEMP_DIRECTORY")

        self.assertEqual(result, "/tmp")

    def test_get_variable_invalid_variable(self):
        # Test when an invalid variable is provided
        result = self.azure_devops.get_variable("INVALID_VARIABLE")

        self.assertIsNone(result)
        
    def test_get_variable_system_access_token(self):
        # Mock the SystemVariables class
        with unittest.mock.patch('devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.azure_devops.azure_devops.SystemVariables') as mock_system_variables:
            mock_system_variables.System_AccessToken.value.return_value = "SYSTEM_ACCESSTOKEN"

            result = self.azure_devops.get_variable("ACCESS_TOKEN")

        self.assertEqual(result, "SYSTEM_ACCESSTOKEN")
    
    def test_get_variable_system_team_foundation_collection_uri(self):
        # Mock the SystemVariables class
        with unittest.mock.patch('devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.azure_devops.azure_devops.SystemVariables') as mock_system_variables:
            mock_system_variables.System_TeamFoundationCollectionUri.value.return_value = "https://ORGANIZATION"

            result = self.azure_devops.get_variable("ORGANIZATION")

        self.assertEqual(result, "https://ORGANIZATION")
    
    def test_get_variable_system_team_project_id(self):
        # Mock the SystemVariables class
        with unittest.mock.patch('devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.azure_devops.azure_devops.SystemVariables') as mock_system_variables:
            mock_system_variables.System_TeamProjectId.value.return_value = "SYSTEM_TEAM_PROJECT_ID"

            result = self.azure_devops.get_variable("PROJECT_ID")

        self.assertEqual(result, "SYSTEM_TEAM_PROJECT_ID")
    
    def test_get_variable_system_pull_request_id(self):
        # Mock the SystemVariables class
        with unittest.mock.patch('devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.azure_devops.azure_devops.SystemVariables') as mock_system_variables:
            mock_system_variables.System_PullRequestId.value.return_value = "SYSTEM_PULLREQUEST_ID"

            result = self.azure_devops.get_variable("PR_ID")

        self.assertEqual(result, "SYSTEM_PULLREQUEST_ID")

    @patch('requests.get')
    @mock.patch(
        "devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.azure_devops.azure_devops.SystemVariables",
        autospec=True,
    )
    def test_get_pullrequest_iterations_request_error(self, mock_get, mock_system_variables):
        mock_system_variables.System_TeamFoundationCollectionUri.value.return_value = (
            "System_TeamFoundationCollectionUri"
        )
        azure_devops = AzureDevops()
        mock_get.side_effect = requests.RequestException("Error")

        results = azure_devops.get_pullrequest_iterations("repository_name", "pr_id")

        assert results == []

    @patch(
        "devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.azure_devops.azure_devops.SystemVariables",
        autospec=True,
    )
    @patch('requests.get')
    def test_get_commits_files_success(self, mock_get, mock_system_variables):
        mock_system_variables.return_value.System_TeamFoundationCollectionUri.value.return_value = "System_TeamFoundationCollectionUri"

        mock_pr_response = MagicMock()
        mock_pr_response.status_code = 200
        mock_pr_response.json.return_value = {
            "changes": [{"item": {"gitObjectType": "blob", "path": "/file1.py"}}]
        }
        # mock_get.side_effect = [mock_pr_response]
        mock_get.return_value = mock_pr_response

        with unittest.mock.patch('devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.azure_devops.azure_devops.SystemVariables') as mock_system_variables2:
            mock_system_variables2.System_DefaultWorkingDirectory.value.return_value = "/path/to/working/dir"

            # Ejecutar el método bajo prueba
            azure_devops = AzureDevops()
            commits = [{"sourceRefCommit": {"commitId": "e6c3acf12218202069e5bfcce75f9541f8ecfe8c"}}]
            headers = {}
            results = []
            azure_devops.get_commits_files(commits, results, "repository_name", headers)

            # Verificar resultados
            assert results == ["/path/to/working/dir/file1.py"]

    @patch('requests.get')
    def test_get_commits_files_request_error(mock_get, azure_devops_instance):
        mock_get.side_effect = requests.RequestException("Error")

        results = []
        azure_devops_instance.get_commits_files([{"sourceRefCommit": {"commitId": "commit_id_1"}}], results, "repository_name", {})

        assert results == []
    
    def test_message(self):
        azure_devops = AzureDevops()

        assert azure_devops.message("succeeded", "message") == "##[section]message"
        assert azure_devops.message("info", "message") == "##[command]message"
        assert azure_devops.message("warning", "message") == "##[warning]message"
        assert azure_devops.message("error", "message") == "##[error]message"