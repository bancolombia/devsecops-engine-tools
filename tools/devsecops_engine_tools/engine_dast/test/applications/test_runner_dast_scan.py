import unittest
from unittest import mock
from devsecops_engine_tools.engine_dast.src.applications.runner_dast_scan import (
    runner_engine_dast
)
from devsecops_engine_tools.engine_dast.src.domain.model.api_config import ApiConfig

class TestRunnerEngineDast(unittest.TestCase):

    @mock.patch('devsecops_engine_tools.engine_dast.src.applications.runner_dast_scan.load_json_file')
    @mock.patch('devsecops_engine_tools.engine_dast.src.applications.runner_dast_scan.init_engine_dast')
    @mock.patch('devsecops_engine_tools.engine_dast.src.applications.runner_dast_scan.NucleiTool')
    @mock.patch('devsecops_engine_tools.engine_dast.src.applications.runner_dast_scan.JwtTool')
    @mock.patch('devsecops_engine_tools.engine_dast.src.applications.runner_dast_scan.ApiConfig')
    @mock.patch('os.environ', {'GITHUB_TOKEN': 'example_token'})
    def test_runner_engine_dast_with_jwt(self, mock_api_config,mock_jwt_tool, mock_nuclei_tool,
                                         mock_init_engine_dast, mock_load_json_file):
        # Configurar los valores de retorno de los mocks
        mock_load_json_file.return_value = {
            "endpoint": "https://example.com",
            "operations": [
                {
                    "operation": {
                        "headers": {"accept": "/"},
                        "method": "POST",
                        "path": "/example_path",
                        "security_auth": {"type": "jwt"}
                    }
                }
            ]
        }
        mock_nuclei_tool_instance = mock_nuclei_tool.return_value
        mock_jwt_tool_instance = mock_jwt_tool.return_value
        mock_init_engine_dast.return_value = (["finding1", "finding2"], "input_core_mock")

        # Mock de ApiConfig
        mock_api_config_instance = mock_api_config.return_value

        # Configurar los argumentos
        dict_args = {
            "use_secrets_manager": "true",
            "tool": "engine_dast",
            "dast_file_path": "example_dast.json"
        }
        config_tool = {"ENGINE_DAST": {"ENABLED": "true", "TOOL": "NUCLEI", "EXTRA_TOOLS": ["JWT"]}}
        secret_tool = {"github_token": "example_token"}
        devops_platform_gateway = mock.Mock()

        # Llamar a la función
        findings_list, input_core = runner_engine_dast(dict_args, config_tool, secret_tool, devops_platform_gateway)

        # Verificar que las funciones mockeadas fueron llamadas correctamente
        mock_load_json_file.assert_called_once_with(dict_args["dast_file_path"])
        mock_init_engine_dast.assert_called_once_with(
            devops_platform_gateway=devops_platform_gateway,
            tool_gateway=mock_nuclei_tool_instance,
            dict_args=dict_args,
            checks_token='example_token',
            config_tool=config_tool,
            extra_tools=[mock_jwt_tool_instance],
            target_data=mock_api_config_instance  # Verificar contra el mock de ApiConfig
        )

        # Verificar los resultados
        self.assertEqual(findings_list, ["finding1", "finding2"])
        self.assertEqual(input_core, "input_core_mock")

    @mock.patch('devsecops_engine_tools.engine_dast.src.applications.runner_dast_scan.load_json_file')
    @mock.patch('devsecops_engine_tools.engine_dast.src.applications.runner_dast_scan.init_engine_dast')
    @mock.patch('devsecops_engine_tools.engine_dast.src.applications.runner_dast_scan.NucleiTool')
    @mock.patch('devsecops_engine_tools.engine_dast.src.applications.runner_dast_scan.ApiConfig')
    @mock.patch('os.environ', {'GITHUB_TOKEN': 'example_token'})
    def test_runner_engine_dast_with_oauth(self,
            mock_api_config,
            mock_nuclei_tool,
            mock_init_engine_dast,
            mock_load_json_file):
        # Configurar los valores de retorno de los mocks
        mock_load_json_file.return_value = {
            "endpoint": "https://example.com",
            "operations": [
                {
                    "operation": {
                        "headers": {"accept": "/"},
                        "method": "POST",
                        "path": "/example_path",
                        "security_auth": {"type": "oauth"}
                    }
                }
            ]
        }
        mock_nuclei_tool_instance = mock_nuclei_tool.return_value
        mock_init_engine_dast.return_value = (["finding1", "finding2"], "input_core_mock")
        
        # Mock de ApiConfig
        mock_api_config_instance = mock_api_config.return_value

        # Configurar los argumentos
        dict_args = {
            "use_secrets_manager": "true",
            "tool": "engine_dast",
            "dast_file_path": "example_dast.json"
        }
        config_tool = {"ENGINE_DAST": {"ENABLED": "true", "TOOL": "NUCLEI", "EXTRA_TOOLS": []}}
        secret_tool = {"github_token": "example_token"}
        devops_platform_gateway = mock.Mock()

        # Llamar a la función
        findings_list, input_core = runner_engine_dast(dict_args, config_tool, secret_tool, devops_platform_gateway)

        # Verificar que las funciones mockeadas fueron llamadas correctamente
        mock_load_json_file.assert_called_once_with(dict_args["dast_file_path"])
        mock_init_engine_dast.assert_called_once_with(
            devops_platform_gateway=devops_platform_gateway,
            tool_gateway=mock_nuclei_tool_instance,
            dict_args=dict_args,
            checks_token='example_token',
            config_tool=config_tool,
            extra_tools=[],
            target_data=mock_api_config_instance  # Verificar contra el mock de ApiConfig
        )

        # Verificar los resultados
        self.assertEqual(findings_list, ["finding1", "finding2"])
        self.assertEqual(input_core, "input_core_mock")

    @mock.patch('devsecops_engine_tools.engine_dast.src.applications.runner_dast_scan.load_json_file')
    @mock.patch('devsecops_engine_tools.engine_dast.src.applications.runner_dast_scan.init_engine_dast')
    @mock.patch('devsecops_engine_tools.engine_dast.src.applications.runner_dast_scan.NucleiTool')
    def test_runner_engine_dast_with_invalid_target(self, mock_nuclei_tool, mock_init_engine_dast, mock_load_json_file):
        # Configurar los valores de retorno de los mocks
        mock_load_json_file.return_value = {
            "invalid_key": "invalid_value"
        }

        # Configurar los argumentos
        dict_args = {
            "use_secrets_manager": "true",
            "tool": "engine_dast",
            "dast_file_path": "example_dast.json"
        }
        config_tool = {"ENGINE_DAST": {"ENABLED": "true", "TOOL": "NUCLEI", "EXTRA_TOOLS": []}}
        secret_tool = {"github_token": "example_token"}
        devops_platform_gateway = mock.Mock()

        # Verificar que se lanza una excepción para el target inválido
        with self.assertRaises(ValueError):
            runner_engine_dast(dict_args, config_tool, secret_tool, devops_platform_gateway)
