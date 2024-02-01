import unittest
from unittest.mock import MagicMock
from unittest import mock
from devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.azure_devops.azure_devops import (
    AzureDevops,
)


class TestAzureDevops(unittest.TestCase):
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

    @mock.patch(
        "devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.azure_devops.azure_devops.ReleaseVariables",
        autospec=True,
    )
    def test_get_variable_BUILD_REPOSITORY_NAME(self, mock_release_variables):
        azure_devops = AzureDevops()

        # Mock the ReleaseVariables class
        mock_release_variables.Release_Definitionname.value.return_value = (
            "BUILD_REPOSITORY_NAME"
        )

        result = azure_devops.get_variable("BUILD_REPOSITORY_NAME")
        assert result == "BUILD_REPOSITORY_NAME"
        
    @mock.patch(
    "devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.azure_devops.azure_devops.ReleaseVariables",
    autospec=True,
    )
    def test_get_variable_SYSTEM_DEFAULTWORKINGDIRECTORYE(self, mock_release_variables):
        azure_devops = AzureDevops()

        # Mock the ReleaseVariables class
        mock_release_variables.Release_Definitionname.value.return_value = (
            "SYSTEM_DEFAULTWORKINGDIRECTORY"
        )

        result = azure_devops.get_variable("SYSTEM_DEFAULTWORKINGDIRECTORY")
        assert result == "SYSTEM_DEFAULTWORKINGDIRECTORY"

    @mock.patch("devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.azure_devops.azure_devops.BuildVariables", autospec=True)
    def test_get_variable_exception(self, mock_build_variables):
        azure_devops = AzureDevops()

        # Simular una excepción al intentar obtener la variable
        mock_build_variables.Build_Repository_Name.value.side_effect = Exception("Simulated exception")

        with self.assertLogs(level="WARNING") as log:
            result = azure_devops.get_variable("BUILD_REPOSITORY_NAME")

        # Verificar que la excepción fue registrada en los logs
        self.assertIn("Error getting variable Simulated exception", log.output)

        # Verificar que el resultado es None
        self.assertIsNone(result)