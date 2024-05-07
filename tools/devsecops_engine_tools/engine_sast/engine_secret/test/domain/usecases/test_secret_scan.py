import unittest
from unittest.mock import patch
from devsecops_engine_tools.engine_core.src.domain.model.input_core import InputCore
from devsecops_engine_tools.engine_sast.engine_secret.src.domain.usecases.secret_scan import (
    SecretScan,
)


class TestSecretScan(unittest.TestCase):

    @patch('devsecops_engine_tools.engine_sast.engine_secret.src.domain.model.gateway.git_gateway.GitGateway')
    @patch(
        "devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway.DevopsPlatformGateway"
    )
    @patch(
        "devsecops_engine_tools.engine_sast.engine_secret.src.domain.model.gateway.gateway_deserealizator.DeseralizatorGateway"
    )
    @patch(
        "devsecops_engine_tools.engine_sast.engine_secret.src.domain.model.gateway.tool_gateway.ToolGateway"
    )
    def test_process(
        self, mock_tool_gateway, mock_devops_gateway, mock_deserialize_gateway, mock_git_gateway
    ):
        # Configuración de mocks
        mock_tool_gateway_instance = mock_tool_gateway.return_value
        mock_devops_gateway_instance = mock_devops_gateway.return_value
        mock_deserialize_gateway_instance = mock_deserialize_gateway.return_value
        mock_git_gateway_instance = mock_git_gateway.return_value

        secret_scan = SecretScan(
            mock_tool_gateway_instance,
            mock_devops_gateway_instance,
            mock_deserialize_gateway_instance,
            mock_git_gateway_instance
        )

        mock_deserialize_gateway_instance.get_list_vulnerability.return_value = [
            "vulnerability_data"
        ]

        json_config = {
            "IGNORE_SEARCH_PATTERN": ["test"],
            "MESSAGE_INFO_ENGINE_SECRET": "message test",
            "THRESHOLD": {
                "VULNERABILITY": {"Critical": 1, "High": 1, "Medium": 1, "Low": 1},
                "COMPLIANCE": {"Critical": 1},
            },
            "TARGET_BRANCHES": ['trunk', 'develop'],
            "trufflehog": {"EXCLUDE_PATH": [".git"], "NUMBER_THREADS": 4},
        }

        mock_devops_gateway_instance.get_remote_config.return_value = json_config
        mock_devops_gateway_instance.get_variable.return_value = "example_pipeline"
        mock_tool_gateway_instance.run_tool_secret_scan.return_value = (
            "vulnerability_data"
        )

        # Llamada al método a probar
        finding_list, input_core = secret_scan.process(
            {"remote_config_repo": "some_repo"}, "trufflehog"
        )

        self.assertEqual(finding_list, ["vulnerability_data"])
        mock_tool_gateway_instance.install_tool.assert_called_once()
        mock_tool_gateway_instance.run_tool_secret_scan.assert_called_once()

    @patch('devsecops_engine_tools.engine_sast.engine_secret.src.domain.model.gateway.git_gateway.GitGateway')
    @patch(
        "devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway.DevopsPlatformGateway"
    )
    @patch(
        "devsecops_engine_tools.engine_sast.engine_secret.src.domain.model.gateway.gateway_deserealizator.DeseralizatorGateway"
    )
    @patch(
        "devsecops_engine_tools.engine_sast.engine_secret.src.domain.model.gateway.tool_gateway.ToolGateway"
    )
    def test_process_empty(
        self, mock_tool_gateway, mock_devops_gateway, mock_deserialize_gateway, mock_git_gateway
    ):
        # Configuración de mocks
        mock_tool_gateway_instance = mock_tool_gateway.return_value
        mock_devops_gateway_instance = mock_devops_gateway.return_value
        mock_deserialize_gateway_instance = mock_deserialize_gateway.return_value
        mock_git_gateway_instance = mock_git_gateway.return_value

        secret_scan = SecretScan(
            mock_tool_gateway_instance,
            mock_devops_gateway_instance,
            mock_deserialize_gateway_instance,
            mock_git_gateway_instance
        )

        mock_deserialize_gateway_instance.get_list_vulnerability.return_value = []

        json_config = {
            "IGNORE_SEARCH_PATTERN": ["test"],
            "MESSAGE_INFO_ENGINE_SECRET": "message test",
            "THRESHOLD": {
                "VULNERABILITY": {"Critical": 1, "High": 1, "Medium": 1, "Low": 1},
                "COMPLIANCE": {"Critical": 1},
            },
            "TARGET_BRANCHES": ['trunk', 'develop'],
            "trufflehog": {
                "EXCLUDE_PATH": [".git"],
                "NUMBER_THREADS": 4
            },
        }

        mock_devops_gateway_instance.get_remote_config.return_value = json_config
        mock_devops_gateway_instance.get_variable.return_value = "example_pipeline"
        mock_tool_gateway_instance.run_tool_secret_scan.return_value = ""

        finding_list, input_core = secret_scan.process(
            {"remote_config_repo": "some_repo"}, "trufflehog"
        )

        self.assertEqual(finding_list, [])
        mock_tool_gateway_instance.install_tool.assert_called_once()
        mock_tool_gateway_instance.run_tool_secret_scan.assert_called_once()
