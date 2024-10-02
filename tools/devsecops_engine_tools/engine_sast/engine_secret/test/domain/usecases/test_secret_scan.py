import unittest
from unittest.mock import patch
from devsecops_engine_tools.engine_core.src.domain.model.input_core import InputCore
from devsecops_engine_tools.engine_sast.engine_secret.src.domain.usecases.secret_scan import (
    SecretScan,
)
from devsecops_engine_tools.engine_sast.engine_secret.src.domain.model.DeserializeConfigTool import (
    DeserializeConfigTool,
)

class TestSecretScan(unittest.TestCase):
    def setUp(self) -> None:
        global json_config
        json_config = {
            "IGNORE_SEARCH_PATTERN": [
                "test"
            ],
            "MESSAGE_INFO_ENGINE_SECRET": "If you have doubts, visit url",
            "THRESHOLD": {
                "VULNERABILITY": {
                    "Critical": 1,
                    "High": 1,
                    "Medium": 1,
                    "Low": 1
                },
                "COMPLIANCE": {
                    "Critical": 0
                }
            },
            "TARGET_BRANCHES": ["trunk", "develop"],
            "trufflehog": {
                "EXCLUDE_PATH": [".git", "node_modules", "target", "build", "build.gradle", "twistcli-scan", ".svg", ".drawio"],
                "NUMBER_THREADS": 4,
                "ENABLE_CUSTOM_RULES" : "True",
                "EXTERNAL_DIR_OWNER": "ExternalOrg",
                "EXTERNAL_DIR_REPOSITORY": "DevSecOps_Checks"
            }
        }

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

        secret_tool = "secret"

        secret_scan = SecretScan(
            mock_tool_gateway_instance,
            mock_devops_gateway_instance,
            mock_deserialize_gateway_instance,
            mock_git_gateway_instance
        )

        mock_deserialize_gateway_instance.get_list_vulnerability.return_value = [
            "vulnerability_data"
        ]

        obj_config_tool = DeserializeConfigTool(json_config, 'trufflehog')
        mock_devops_gateway_instance.get_remote_config.return_value = json_config
        mock_devops_gateway_instance.get_variable.return_value = "example_pipeline"
        mock_tool_gateway_instance.run_tool_secret_scan.return_value = (
            "vulnerability_data", "path/findings"
        )

        finding_list, file_path_findings = secret_scan.process(
            False, obj_config_tool, secret_tool
        )

        self.assertEqual(finding_list, ["vulnerability_data"])
        self.assertEqual(file_path_findings, "path/findings")
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

        secret_tool = "secret"

        secret_scan = SecretScan(
            mock_tool_gateway_instance,
            mock_devops_gateway_instance,
            mock_deserialize_gateway_instance,
            mock_git_gateway_instance
        )

        mock_deserialize_gateway_instance.get_list_vulnerability.return_value = []

        obj_config_tool = DeserializeConfigTool(json_config, 'trufflehog')
        mock_devops_gateway_instance.get_remote_config.return_value = json_config
        mock_devops_gateway_instance.get_variable.return_value = "example_pipeline"
        mock_tool_gateway_instance.run_tool_secret_scan.return_value = "", ""

        finding_list, file_path_findings = secret_scan.process(
            False, obj_config_tool, secret_tool
        )

        self.assertEqual(finding_list, [])
        self.assertEqual(file_path_findings, "")
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
    def test_skip_tool_true(self, mock_tool_gateway, mock_devops_gateway, mock_deserialize_gateway, mock_git_gateway):
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

        mock_devops_gateway_instance = mock_devops_gateway.return_value
        mock_devops_gateway_instance.get_variable.return_value = "test_pipeline"
        exclusions = {
            "test_pipeline": {"SKIP_TOOL": 1}
        }
        result = secret_scan.skip_from_exclusion(exclusions)
        self.assertTrue(result)

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
    def test_skip_tool_false(self, mock_tool_gateway, mock_devops_gateway, mock_deserialize_gateway, mock_git_gateway):
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

        mock_devops_gateway_instance = mock_devops_gateway.return_value
        mock_devops_gateway_instance.get_variable.return_value = "other_pipeline"
        exclusions = {
            "test_pipeline": {"SKIP_TOOL": 1}
        }
        result = secret_scan.skip_from_exclusion(exclusions)
        self.assertFalse(result)
    
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
    def test_complete_config_tool(
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

        mock_devops_gateway_instance.get_remote_config.return_value = json_config
        mock_devops_gateway_instance.get_variable.return_value = "example_pipeline"

        config_tool_instance = secret_scan.complete_config_tool(
            {"remote_config_repo": "repository"}, "TRUFFLEHOG"
        )

        self.assertEqual(config_tool_instance.scope_pipeline, "example_pipeline")