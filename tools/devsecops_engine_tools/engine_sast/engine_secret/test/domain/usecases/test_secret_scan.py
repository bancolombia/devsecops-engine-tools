import unittest
from unittest.mock import Mock, patch
from devsecops_engine_tools.engine_core.src.domain.model.input_core import InputCore
from devsecops_engine_tools.engine_sast.engine_secret.src.domain.model.DeserializeConfigTool import DeserializeConfigTool
from devsecops_engine_tools.engine_sast.engine_secret.src.domain.model.gateway.tool_gateway import ToolGateway
from devsecops_engine_tools.engine_sast.engine_secret.src.domain.model.gateway.gateway_deserealizator import DeseralizatorGateway
from devsecops_engine_tools.engine_sast.engine_secret.src.domain.model.gateway.devops_platform_gateway import DevopsPlatformGateway
from devsecops_engine_tools.engine_sast.engine_secret.src.domain.usecases.secret_scan import SecretScan

class TestSecretScan(unittest.TestCase):

    @patch('devsecops_engine_tools.engine_sast.engine_secret.src.domain.model.gateway.devops_platform_gateway.DevopsPlatformGateway')
    @patch('devsecops_engine_tools.engine_sast.engine_secret.src.domain.model.gateway.gateway_deserealizator.DeseralizatorGateway')
    @patch('devsecops_engine_tools.engine_sast.engine_secret.src.domain.model.gateway.tool_gateway.ToolGateway')
    def test_process(self, mock_tool_gateway, mock_devops_gateway, mock_deserialize_gateway):
        # Configuración de mocks
        mock_tool_gateway_instance = mock_tool_gateway.return_value
        mock_devops_gateway_instance = mock_devops_gateway.return_value
        mock_deserialize_gateway_instance = mock_deserialize_gateway.return_value
        
        # Configuración de la instancia de SecretScan
        secret_scan = SecretScan(mock_tool_gateway_instance, mock_devops_gateway_instance, mock_deserialize_gateway_instance)

        # Configura el valor de retorno esperado para get_list_vulnerability
        mock_deserialize_gateway_instance.get_list_vulnerability.return_value = ["vulnerability_data"]

        # Configuración de retornos esperados para los mocks
        json_config = {
            "trufflehog": {
                "IGNORE_SEARCH_PATTERN": ["test"],
                "MESSAGE_INFO_SAST_BUILD": "message test",
                "THRESHOLD": {
                    "VULNERABILITY": {
                        "Critical": 1,
                        "High": 1,
                        "Medium": 1,
                        "Low": 1
                    },
                    "COMPLIANCE": {
                        "Critical": 1
                    }
                },
                "EXCLUDE_PATH": [".git"],
                "NUMBER_THREADS": 4
            }
        }

        mock_devops_gateway_instance.get_remote_config.return_value = json_config
        mock_devops_gateway_instance.get_variable.return_value = "example_pipeline"
        mock_tool_gateway_instance.run_tool_secret_scan.return_value = "vulnerability_data"

        # Llamada al método a probar
        finding_list, input_core = secret_scan.process({"remote_config_repo": "some_repo"}, "trufflehog")

        # Verificación de resultados
        expected_input_core = InputCore(
            totalized_exclusions=[],
            threshold_defined=json_config["trufflehog"]["THRESHOLD"]["VULNERABILITY"],
            path_file_results=["vulnerability_data"],
            custom_message_break_build=json_config["trufflehog"]["MESSAGE_INFO_SAST_BUILD"],
            scope_pipeline="example_pipeline",
            stage_pipeline="Build"
        )
        self.assertEqual(finding_list, ["vulnerability_data"])
        self.assertEqual(input_core.totalized_exclusions, [])
        self.assertEqual(input_core.threshold_defined.vulnerability.critical, 1)
        self.assertEqual(input_core.path_file_results, ["vulnerability_data"])
        self.assertEqual(input_core.custom_message_break_build, "message test")
        self.assertEqual(input_core.scope_pipeline, "example_pipeline")
        self.assertEqual(input_core.stage_pipeline, "Build")
        mock_tool_gateway_instance.install_tool.assert_called_once()
        mock_tool_gateway_instance.run_tool_secret_scan.assert_called_once()

    @patch('devsecops_engine_tools.engine_sast.engine_secret.src.domain.model.gateway.devops_platform_gateway.DevopsPlatformGateway')
    @patch('devsecops_engine_tools.engine_sast.engine_secret.src.domain.model.gateway.gateway_deserealizator.DeseralizatorGateway')
    @patch('devsecops_engine_tools.engine_sast.engine_secret.src.domain.model.gateway.tool_gateway.ToolGateway')
    def test_process_empty(self, mock_tool_gateway, mock_devops_gateway, mock_deserialize_gateway):
        # Configuración de mocks
        mock_tool_gateway_instance = mock_tool_gateway.return_value
        mock_devops_gateway_instance = mock_devops_gateway.return_value
        mock_deserialize_gateway_instance = mock_deserialize_gateway.return_value
        
        # Configuración de la instancia de SecretScan
        secret_scan = SecretScan(mock_tool_gateway_instance, mock_devops_gateway_instance, mock_deserialize_gateway_instance)

        # Configura el valor de retorno esperado para get_list_vulnerability
        mock_deserialize_gateway_instance.get_list_vulnerability.return_value = []

        # Configuración de retornos esperados para los mocks
        json_config = {
            "trufflehog": {
                "IGNORE_SEARCH_PATTERN": ["test"],
                "MESSAGE_INFO_SAST_BUILD": "message test",
                "THRESHOLD": {
                    "VULNERABILITY": {
                        "Critical": 1,
                        "High": 1,
                        "Medium": 1,
                        "Low": 1
                    },
                    "COMPLIANCE": {
                        "Critical": 1
                    }
                },
                "EXCLUDE_PATH": [".git"],
                "NUMBER_THREADS": 4
            }
        }

        mock_devops_gateway_instance.get_remote_config.return_value = json_config
        mock_devops_gateway_instance.get_variable.return_value = "example_pipeline"
        mock_tool_gateway_instance.run_tool_secret_scan.return_value = ""

        # Llamada al método a probar
        finding_list, input_core = secret_scan.process({"remote_config_repo": "some_repo"}, "trufflehog")

        # Verificación de resultados
        expected_input_core = InputCore(
            totalized_exclusions=[],
            threshold_defined=json_config["trufflehog"]["THRESHOLD"]["VULNERABILITY"],
            path_file_results=[],
            custom_message_break_build=json_config["trufflehog"]["MESSAGE_INFO_SAST_BUILD"],
            scope_pipeline="example_pipeline",
            stage_pipeline="Build"
        )
        self.assertEqual(finding_list, [])
        self.assertEqual(input_core.totalized_exclusions, [])
        self.assertEqual(input_core.threshold_defined.vulnerability.critical, 1)
        self.assertEqual(input_core.path_file_results, [])
        self.assertEqual(input_core.custom_message_break_build, "message test")
        self.assertEqual(input_core.scope_pipeline, "example_pipeline")
        self.assertEqual(input_core.stage_pipeline, "Build")
        mock_tool_gateway_instance.install_tool.assert_called_once()
        mock_tool_gateway_instance.run_tool_secret_scan.assert_called_once()