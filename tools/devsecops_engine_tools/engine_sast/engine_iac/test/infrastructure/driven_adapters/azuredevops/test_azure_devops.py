import unittest
from unittest.mock import MagicMock
from unittest import mock
from devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.azure.azure_devops import AzureDevops

class TestAzureDevops(unittest.TestCase):

    @mock.patch('devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.azure.azure_devops.AzureDevopsApi', autospec=True)
    @mock.patch('devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.azure.azure_devops.SystemVariables', autospec=True)
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

    def test_logging(self):
        azure_devops = AzureDevops()

        assert azure_devops.logging("succeeded", "message") == "##[section]message"
        assert azure_devops.logging("info", "message") == "##[command]message"
        assert azure_devops.logging("warning", "message") == "##[warning]message"
        assert azure_devops.logging("error", "message") == "##[error]message"

    @mock.patch('devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.azure.azure_devops.ReleaseVariables', autospec=True)
    def test_get_variable(self, mock_release_variables):
        azure_devops = AzureDevops()

        # Mock the ReleaseVariables class
        mock_release_variables.Release_Definitionname.value.return_value = "Release_Definitionname"
        
        result = azure_devops.get_variable("pipeline")
        assert result == "Release_Definitionname"