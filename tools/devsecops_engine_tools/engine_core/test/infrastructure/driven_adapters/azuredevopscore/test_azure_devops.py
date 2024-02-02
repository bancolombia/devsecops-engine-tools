import unittest
from unittest.mock import MagicMock
from unittest import mock
from devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.azure.azure_devops import AzureDevops

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
        mock_build_variables.System_TeamProject.value.return_value = "Build_Project_Name"
        mock_build_variables.Build_Repository_Name.value.return_value = "Build_Repository_Name"

        assert azure_devops.get_source_code_management_uri() == "System_TeamFoundationCollectionUriBuild_Project_Name/_git/Build_Repository_Name"

    @mock.patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.azure.azure_devops.SystemVariables', autospec=True)
    def test_get_base_compact_remote_config_url(self, mock_system_variables):
        azure_devops = AzureDevops()

        mock_system_variables.System_TeamFoundationCollectionUri.value.return_value = "System_TeamFoundationCollectionUri"
        mock_system_variables.System_TeamProject.value.return_value = "Build_Project_Name"

        assert azure_devops.get_base_compact_remote_config_url("my_repo") == "https://System_TeamFoundationCollectionUri.visualstudio.com/Build_Project_Name/_git/my_repo?path=/"


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
