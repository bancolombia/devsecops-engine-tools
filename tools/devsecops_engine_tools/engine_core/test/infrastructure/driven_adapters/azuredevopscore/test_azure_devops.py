import os
import unittest
from unittest.mock import MagicMock
from unittest import mock

from devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.azure.azure_devops import AzureDevops
from tools.devsecops_engine_tools.engine_utilities.azuredevops.models import AzurePredefinedVariables

class TestAzureDevops(unittest.TestCase):


    @mock.patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.azure.azure_devops.AzureDevopsApi', autospec=True)
    @mock.patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.azure.azure_devops.SystemVariables', autospec=True)
    def test_get_remote_config(self, mock_system_variables, mock_azure_devops_api):
        azure_devops = AzureDevops()
        # Set up mock values for SystemVariables
        mock_system_variables.System_TeamFoundationCollectionUri.value.return_value = "System_TeamFoundationCollectionUri"
        # Mock the AzureDevopsApi class
        mock_azure_devops_api_instance = MagicMock()
        mock_azure_devops_api_instance.get_azure_connection.return_value = "MockedConnection"
        mock_azure_devops_api_instance.get_remote_json_config.return_value = {'key': 'value'}
        mock_azure_devops_api.return_value = mock_azure_devops_api_instance
        remote_config_repo = "my_repo"
        remote_config_path = "my_path"
        # Llamar con los nuevos argumentos
        result = azure_devops.get_remote_config(remote_config_repo, remote_config_path)
        assert result == {"key": "value"}

    def test_message(self):
        azure_devops = AzureDevops()
        assert azure_devops.message("succeeded", "message") == "##[section]message"
        assert azure_devops.message("info", "message") == "##[command]message"
        assert azure_devops.message("warning", "message") == "##[warning]message"
        assert azure_devops.message("error", "message") == "##[error]message"

    def test_result_pipeline(self):
        azure_devops = AzureDevops()
        assert azure_devops.result_pipeline("failed") == "##vso[task.complete result=Failed;]DONE"
        assert azure_devops.result_pipeline("succeeded") == "##vso[task.complete result=Succeeded;]DONE"

    @mock.patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.azure.azure_devops.SystemVariables', autospec=True)
    @mock.patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.azure.azure_devops.BuildVariables', autospec=True)
    def test_get_source_code_management_uri(self, mock_build_variables, mock_system_variables):
        azure_devops = AzureDevops()
        mock_system_variables.System_TeamFoundationCollectionUri.value.return_value = "System_TeamFoundationCollectionUri"
        mock_system_variables.System_TeamProject.value.return_value = "Build_Project_Name"
        mock_build_variables.Build_Repository_Name.value.return_value = "Build_Repository_Name"
        mock_build_variables.Build_Repository_Provider.value.return_value = "tfsgit"
        assert azure_devops.get_source_code_management_uri() == "System_TeamFoundationCollectionUriBuild_Project_Name/_git/Build_Repository_Name"


    @mock.patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.azure.azure_devops.SystemVariables', autospec=True)
    @mock.patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.azure.azure_devops.BuildVariables', autospec=True)
    def test_get_build_pipeline_execution_url(self, mock_build_variables, mock_system_variables):
        azure_devops = AzureDevops()
        mock_system_variables.System_TeamFoundationCollectionUri.value.return_value = "System_TeamFoundationCollectionUri"
        mock_system_variables.System_TeamProject.value.return_value = "Build_Project_Name"
        mock_build_variables.Build_BuildId.value.return_value = "Build_BuildId"
        assert azure_devops.get_build_pipeline_execution_url() == "System_TeamFoundationCollectionUriBuild_Project_Name/_build?buildId=Build_BuildId"


    @mock.patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.azure.azure_devops.SystemVariables', autospec=True)
    @mock.patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.azure.azure_devops.BuildVariables', autospec=True)
    @mock.patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.azure.azure_devops.ReleaseVariables', autospec=True)
    def test_get_variable(self, mock_release_variables, mock_build_variables, mock_system_variables):
        azure_devops = AzureDevops()
        # Mock the BuildVariables class
        mock_build_variables.Build_SourceBranchName.value.return_value = "Build_SourceBranchName"
        mock_build_variables.Build_BuildNumber.value.return_value = "Build_BuildNumber"
        mock_build_variables.Build_BuildId.value.return_value = "Build_BuildId"
        mock_build_variables.Build_SourceVersion.value.return_value = "Build_SourceVersion"
        mock_build_variables.Build_SourceBranch.value.return_value = "Build_SourceBranch"
        # Mock the ReleaseVariables class
        mock_release_variables.Environment.value.return_value = "Environment"
        mock_release_variables.Release_Releaseid.value.return_value = "Release_ReleaseId"
        # Mock the SystemVariables class
        mock_system_variables.System_AccessToken.value.return_value = "System_AccessToken"
        result = azure_devops.get_variable("branch_name")
        assert result == "Build_SourceBranchName"
        result = azure_devops.get_variable("build_id")
        assert result == "Build_BuildNumber"
        result = azure_devops.get_variable("build_execution_id")
        assert result == "Build_BuildId"
        result = azure_devops.get_variable("commit_hash")
        assert result == "Build_SourceVersion"
        result = azure_devops.get_variable("environment")
        assert result == "Environment"
        result = azure_devops.get_variable("release_id")
        assert result == "Release_ReleaseId"
        result = azure_devops.get_variable("branch_tag")
        assert result == "Build_SourceBranch"
        result = azure_devops.get_variable("access_token")
        assert result == "System_AccessToken"

class TestEnvVariables(unittest.TestCase):
    @mock.patch('os.environ.get')
    def test_get_value_variable_exists(self, mock_env_get):
        # Arrange
        mock_env_get.return_value = "test_value"
        
        # Act
        result = AzurePredefinedVariables.EnvVariables.get_value("TEST_VARIABLE")
        
        # Assert
        self.assertEqual(result, "test_value")
        mock_env_get.assert_called_once_with("TEST_VARIABLE")

    @mock.patch('os.environ.get')
    def test_get_value_variable_not_exists(self, mock_env_get):
        # Arrange
        mock_env_get.return_value = None
        
        # Act & Assert
        with self.assertRaises(ValueError) as context:
            AzurePredefinedVariables.EnvVariables.get_value("TEST_VARIABLE")
        self.assertEqual(str(context.exception), "La variable de entorno TEST_VARIABLE no está definida")
        mock_env_get.assert_called_once_with("TEST_VARIABLE")

    @mock.patch('os.environ.get')
    def test_get_value_custom_repository_name_none(self, mock_env_get):
        # Arrange
        mock_env_get.return_value = None
        
        # Act
        result = AzurePredefinedVariables.EnvVariables.get_value("CUSTOM_REPOSITORY_NAME")
        
        # Assert
        self.assertIsNone(result)
        mock_env_get.assert_called_once_with("CUSTOM_REPOSITORY_NAME")

    @mock.patch('os.environ.get')
    def test_get_value_custom_pipeline_name_none(self, mock_env_get):
        # Arrange
        mock_env_get.return_value = None
        
        # Act
        result = AzurePredefinedVariables.EnvVariables.get_value("CUSTOM_PIPELINE_NAME")
        
        # Assert
        self.assertIsNone(result)
        mock_env_get.assert_called_once_with("CUSTOM_PIPELINE_NAME")

    @mock.patch('os.environ.get')
    def test_get_value_custom_repository_name_exists(self, mock_env_get):
        # Arrange
        mock_env_get.return_value = "repo_name"
        
        # Act
        result = AzurePredefinedVariables.EnvVariables.get_value("CUSTOM_REPOSITORY_NAME")
        
        # Assert
        self.assertEqual(result, "repo_name")
        mock_env_get.assert_called_once_with("CUSTOM_REPOSITORY_NAME")

    @mock.patch('os.environ.get')
    def test_get_value_custom_pipeline_name_exists(self, mock_env_get):
        # Arrange
        mock_env_get.return_value = "pipeline_name"
        
        # Act
        result = AzurePredefinedVariables.EnvVariables.get_value("CUSTOM_PIPELINE_NAME")
        
        # Assert
        self.assertEqual(result, "pipeline_name")
        mock_env_get.assert_called_once_with("CUSTOM_PIPELINE_NAME")


class TestAzureDevopsAdditional(unittest.TestCase):

    def test_result_pipeline_succeeded_with_issues(self):
        azure_devops = AzureDevops()
        result = azure_devops.result_pipeline("succeeded_with_issues")
        self.assertEqual(result, "##vso[task.complete result=SucceededWithIssues;]DONE")

    @mock.patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.azure.azure_devops.SystemVariables', autospec=True)
    @mock.patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.azure.azure_devops.BuildVariables', autospec=True)
    def test_get_source_code_management_uri_github(self, mock_build_variables, mock_system_variables):
        azure_devops = AzureDevops()
        mock_build_variables.Build_Repository_Name.value.return_value = "octocat/hello-world"
        mock_build_variables.Build_Repository_Provider.value.return_value = "github"
        result = azure_devops.get_source_code_management_uri()
        self.assertEqual(result, "https://github.com/octocat/hello-world")

    @mock.patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.azure.azure_devops.SystemVariables', autospec=True)
    @mock.patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.azure.azure_devops.BuildVariables', autospec=True)
    def test_get_source_code_management_uri_git(self, mock_build_variables, mock_system_variables):
        azure_devops = AzureDevops()
        mock_system_variables.System_TeamFoundationCollectionUri.value.return_value = "https://dev.azure.com/org/"
        mock_system_variables.System_TeamProject.value.return_value = "MyProject"
        mock_build_variables.Build_Repository_Name.value.return_value = "MyRepo"
        mock_build_variables.Build_Repository_Provider.value.return_value = "git"
        result = azure_devops.get_source_code_management_uri()
        self.assertEqual(result, "https://dev.azure.com/org/MyProject/_git/MyRepo")

    @mock.patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.azure.azure_devops.SystemVariables', autospec=True)
    @mock.patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.azure.azure_devops.BuildVariables', autospec=True)
    @mock.patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.azure.azure_devops.ReleaseVariables', autospec=True)
    def test_get_variable_value_error_returns_none(self, mock_release_variables, mock_build_variables, mock_system_variables):
        azure_devops = AzureDevops()
        mock_build_variables.Build_SourceBranchName.value.side_effect = ValueError("not defined")
        result = azure_devops.get_variable("branch_name")
        self.assertIsNone(result)

    @mock.patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.azure.azure_devops.logger')
    def test_set_variable(self, mock_logger):
        azure_devops = AzureDevops()
        azure_devops.set_variable("MY_VAR", "my_value")
        mock_logger.info.assert_called_once_with("##vso[task.setvariable variable=MY_VAR;]my_value")

    @mock.patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.azure.azure_devops.SystemVariables', autospec=True)
    @mock.patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.azure.azure_devops.BuildVariables', autospec=True)
    def test_get_source_code_management_uri_value_error_returns_none(self, mock_build_variables, mock_system_variables):
        azure_devops = AzureDevops()
        mock_build_variables.Build_Repository_Provider.value.side_effect = ValueError("not set")
        result = azure_devops.get_source_code_management_uri()
        self.assertIsNone(result)



if __name__ == '__main__':
    unittest.main()