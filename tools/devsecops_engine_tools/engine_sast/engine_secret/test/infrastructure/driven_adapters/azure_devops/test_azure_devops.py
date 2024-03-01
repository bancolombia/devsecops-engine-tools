import unittest
from unittest.mock import patch, MagicMock
from unittest import mock
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
            mock_system_variables.System_DefaultWorkingDirectory.value.return_value = "SYSTEM_ACCESSTOKEN"

            result = self.azure_devops.get_variable("ACCESS_TOKEN")

        self.assertEqual(result, "SYSTEM_ACCESSTOKEN")
    
    def test_get_variable_system_team_foundation_collection_uri(self):
        # Mock the SystemVariables class
        with unittest.mock.patch('devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.azure_devops.azure_devops.SystemVariables') as mock_system_variables:
            mock_system_variables.System_DefaultWorkingDirectory.value.return_value = "https://ORGANIZATION"

            result = self.azure_devops.get_variable("ORGANIZATION")

        self.assertEqual(result, "https://ORGANIZATION")
    
    def test_get_variable_system_team_project_id(self):
        # Mock the SystemVariables class
        with unittest.mock.patch('devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.azure_devops.azure_devops.SystemVariables') as mock_system_variables:
            mock_system_variables.System_DefaultWorkingDirectory.value.return_value = "SYSTEM_TEAM_PROJECT_ID"

            result = self.azure_devops.get_variable("PROJECT_ID")

        self.assertEqual(result, "SYSTEM_TEAM_PROJECT_ID")
    
    def test_get_variable_system_pull_request_id(self):
        # Mock the SystemVariables class
        with unittest.mock.patch('devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.azure_devops.azure_devops.SystemVariables') as mock_system_variables:
            mock_system_variables.System_DefaultWorkingDirectory.value.return_value = "SYSTEM_PULLREQUEST_ID"

            result = self.azure_devops.get_variable("PR_ID")

        self.assertEqual(result, "SYSTEM_PULLREQUEST_ID")