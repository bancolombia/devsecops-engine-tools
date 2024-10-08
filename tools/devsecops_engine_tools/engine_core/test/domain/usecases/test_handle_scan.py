import unittest
from unittest.mock import MagicMock
from unittest import mock
from devsecops_engine_tools.engine_core.src.domain.model.input_core import InputCore
from devsecops_engine_tools.engine_core.src.domain.model.threshold import Threshold
from devsecops_engine_tools.engine_core.src.domain.usecases.handle_scan import (
    HandleScan,
)
from devsecops_engine_tools.engine_core.src.domain.model.customs_exceptions import ( ExceptionVulnerabilityManagement, ExceptionFindingsExcepted)


class TestHandleScan(unittest.TestCase):
    def setUp(self):
        self.vulnerability_management = MagicMock()
        self.secrets_manager_gateway = MagicMock()
        self.devops_platform_gateway = MagicMock()
        self.handle_scan = HandleScan(
            self.vulnerability_management,
            self.secrets_manager_gateway,
            self.devops_platform_gateway,
        )

    @mock.patch(
        "devsecops_engine_tools.engine_core.src.domain.usecases.handle_scan.runner_engine_iac"
    )
    def test_process_with_engine_iac(self, mock_runner_engine_iac):
        dict_args = {
            "use_secrets_manager": "true",
            "tool": "engine_iac",
            "use_vulnerability_management": "true",
            "remote_config_repo": "test_repo",
        }
        config_tool = {"ENGINE_IAC": {"ENABLED": "true", "TOOL": "tool"}}
        secret_tool = "some_secret"
        self.secrets_manager_gateway.get_secret.return_value = secret_tool
        self.devops_platform_gateway.get_variable.return_value = "dev"

        # Mock the runner_engine_iac function and its return values
        findings_list = ["finding1", "finding2"]
        input_core = InputCore(
            totalized_exclusions=[],
            threshold_defined=Threshold,
            path_file_results="test/file",
            custom_message_break_build="message",
            scope_pipeline="pipeline",
            stage_pipeline="Release",
        )
        mock_runner_engine_iac.return_value = findings_list, input_core

        # Mock the send_vulnerability_management method
        self.vulnerability_management.send_vulnerability_management = MagicMock()

        # Mock the get_findings_excepted method
        self.vulnerability_management.get_findings_excepted = MagicMock()
        self.vulnerability_management.get_findings_excepted.return_value = []

        # Call the process method
        result_findings_list, result_input_core = self.handle_scan.process(
            dict_args, config_tool
        )

        # Assert the expected values
        self.assertEqual(result_findings_list, findings_list)
        self.assertEqual(result_input_core, input_core)
        self.secrets_manager_gateway.get_secret.assert_called_once_with(config_tool)
        mock_runner_engine_iac.assert_called_once_with(
            dict_args, config_tool["ENGINE_IAC"]["TOOL"], secret_tool, self.devops_platform_gateway, "dev"
        )
        self.vulnerability_management.send_vulnerability_management.assert_called_once()
        self.vulnerability_management.get_findings_excepted.assert_called_once()

    @mock.patch(
        "devsecops_engine_tools.engine_core.src.domain.usecases.handle_scan.runner_engine_iac"
    )
    def test_process_with_engine_iac_error(self, mock_runner_engine_iac):
        dict_args = {
            "use_secrets_manager": "false",
            "tool": "engine_iac",
            "use_vulnerability_management": "true",
            "remote_config_repo": "test_repo",
        }
        config_tool = {"ENGINE_IAC": {"ENABLED": "true", "TOOL": "tool"}}

        # Mock the runner_engine_iac function and its return values
        findings_list = ["finding1", "finding2"]
        input_core = InputCore(
            totalized_exclusions=[],
            threshold_defined=Threshold,
            path_file_results="test/file",
            custom_message_break_build="message",
            scope_pipeline="pipeline",
            stage_pipeline="Release",
        )
        mock_runner_engine_iac.return_value = findings_list, input_core

        # Mock the send_vulnerability_management method
        self.vulnerability_management.send_vulnerability_management.side_effect = ExceptionVulnerabilityManagement("Simulated error")

        # Mock the get_findings_excepted method
        self.vulnerability_management.get_findings_excepted.side_effect = ExceptionFindingsExcepted("Simulated error")

        # Call the process method
        result_findings_list, result_input_core = self.handle_scan.process(
            dict_args, config_tool
        )

        # Assert the expected values
        self.assertEqual(result_findings_list, findings_list)
        self.assertEqual(result_input_core, input_core)

        self.vulnerability_management.send_vulnerability_management.assert_called_once()
        self.vulnerability_management.get_findings_excepted.assert_called_once()

    @mock.patch(
        "devsecops_engine_tools.engine_core.src.domain.usecases.handle_scan.runner_engine_container"
    )
    def test_process_with_engine_container(self, mock_runner_engine_container):
        dict_args = {
            "use_secrets_manager": "true",
            "tool": "engine_container",
            "remote_config_repo": "test_repo",
            "use_vulnerability_management":"true",
        }
        config_tool = {"ENGINE_CONTAINER": {"ENABLED": "true", "TOOL": "tool"}}
        secret_tool = {"token_prisma_cloud": "test"}
        self.secrets_manager_gateway.get_secret.return_value = secret_tool

        # Mock the runner_engine_iac function and its return values
        findings_list = ["finding1", "finding2"]
        input_core = InputCore(
            totalized_exclusions=[],
            threshold_defined=Threshold,
            path_file_results="test/file",
            custom_message_break_build="message",
            scope_pipeline="pipeline",
            stage_pipeline="Release",
        )
        mock_runner_engine_container.return_value = findings_list, input_core

        # Call the process method
        result_findings_list, result_input_core = self.handle_scan.process(
            dict_args, config_tool
        )

        # Assert the expected values
        self.assertEqual(result_findings_list, findings_list)
        self.assertEqual(result_input_core, input_core)
        self.secrets_manager_gateway.get_secret.assert_called_once_with(config_tool)

    @mock.patch("devsecops_engine_tools.engine_core.src.domain.usecases.handle_scan.runner_engine_dast")
    @mock.patch("builtins.open", new_callable=mock.mock_open, read_data='''{
        "endpoint": "https://example.com",
        "operations": [
            {
                "operation": {
                    "headers": {
                        "accept": "/"
                    },
                    "method": "POST",
                    "path": "/example_path",
                    "security_auth": {
                        "type": "jwt"
                    }
                }
            }
        ]
    }''')
    def test_process_with_engine_dast(self, mock_open, mock_runner_engine_dast):
        dict_args = {
            "use_secrets_manager": "true",
            "tool": "engine_dast",
            "dast_file_path": "example_dast.json"
        }
        secret_tool = {"github_token": "example_token"}
        self.secrets_manager_gateway.get_secret.return_value = secret_tool
        config_tool = {"ENGINE_DAST":{"ENABLED": "true", "TOOL": "NUCLEI"}}
        # Simulates runner_engine_dast return
        mock_runner_engine_dast.return_value = (["finding1", "finding2"], "input_core_mock")
        # Call process method
        result_findings_list, result_input_core = self.handle_scan.process(dict_args, config_tool)
        # Verifies mock have been called correctly
        mock_runner_engine_dast.assert_called_once_with(
            dict_args, config_tool["ENGINE_DAST"], secret_tool, self.devops_platform_gateway
        )
        # Verifica los resultados devueltos
        self.assertEqual(result_findings_list, ["finding1", "finding2"])
        self.assertEqual(result_input_core, "input_core_mock")

    @mock.patch("devsecops_engine_tools.engine_core.src.domain.usecases.handle_scan.runner_secret_scan")
    def test_process_with_engine_secret(self, mock_runner_secret_scan):
        dict_args = {
            "use_secrets_manager": "true",
            "tool": "engine_secret",
            "remote_config_repo": "test_repo",
            "use_vulnerability_management": "true",
        }
        config_tool = {"ENGINE_SECRET": {"ENABLED": "true", "TOOL": "trufflehog"}}
        secret_tool = {"token_github_external_rules": "test"}
        self.secrets_manager_gateway.get_secret.return_value = secret_tool

        # Mock the runner_engine_secret function and its return values
        findings_list = ["finding1", "finding2"]
        input_core = InputCore(
            totalized_exclusions=[],
            threshold_defined=Threshold,
            path_file_results="test/file",
            custom_message_break_build="message",
            scope_pipeline="pipeline",
            stage_pipeline="Release",
        )
        mock_runner_secret_scan.return_value = findings_list, input_core

        # Call the process method
        result_findings_list, result_input_core = self.handle_scan.process(
            dict_args, config_tool
        )

        # Assert the expected values
        self.assertEqual(result_findings_list, findings_list)
        self.assertEqual(result_input_core, input_core)
        mock_runner_secret_scan.assert_called_once_with(
            dict_args, config_tool["ENGINE_SECRET"]["TOOL"], self.devops_platform_gateway, secret_tool
        )

    @mock.patch("devsecops_engine_tools.engine_core.src.domain.usecases.handle_scan.runner_secret_scan")
    def test_process_with_engine_secret_without_secret_manager(self, mock_runner_secret_scan):
        dict_args = {
            "use_secrets_manager": "false",
            "tool": "engine_secret",
            "remote_config_repo": "test_repo",
            "use_vulnerability_management": "true",
        }
        config_tool = {"ENGINE_SECRET": {"ENABLED": "true", "TOOL": "trufflehog"}}
        secret_tool = None
        self.secrets_manager_gateway.get_secret.return_value = secret_tool

        # Mock the runner_engine_secret function and its return values
        findings_list = ["finding1", "finding2"]
        input_core = InputCore(
            totalized_exclusions=[],
            threshold_defined=Threshold,
            path_file_results="test/file",
            custom_message_break_build="message",
            scope_pipeline="pipeline",
            stage_pipeline="Release",
        )
        mock_runner_secret_scan.return_value = findings_list, input_core

        # Call the process method
        result_findings_list, result_input_core = self.handle_scan.process(
            dict_args, config_tool
        )

        # Assert the expected values
        self.assertEqual(result_findings_list, findings_list)
        self.assertEqual(result_input_core, input_core)
        mock_runner_secret_scan.assert_called_once_with(
            dict_args, config_tool["ENGINE_SECRET"]["TOOL"], self.devops_platform_gateway, secret_tool
        )

    @mock.patch(
        "devsecops_engine_tools.engine_core.src.domain.usecases.handle_scan.runner_engine_dependencies"
    )
    def test_process_with_engine_dependencies(self, mock_runner_engine_dependencies):
        dict_args = {
            "use_secrets_manager": "true",
            "tool": "engine_dependencies",
            "remote_config_repo": "test_repo",
            "use_vulnerability_management": "true"
        }
        config_tool = {
            "ENGINE_DEPENDENCIES": "some_config",
            "ENGINE_DEPENDENCIES": {"TOOL": "some_tool"}
        }
        secret_tool = {"token_xray": "test"}
        self.secrets_manager_gateway.get_secret.return_value = secret_tool

        # Mock the runner_engine_dependencies function and its return values
        findings_list = ["finding1", "finding2"]
        input_core = InputCore(
            totalized_exclusions=[],
            threshold_defined=Threshold,
            path_file_results="test/file",
            custom_message_break_build="message",
            scope_pipeline="pipeline",
            stage_pipeline="Release",
        )
        mock_runner_engine_dependencies.return_value = findings_list, input_core

        # Call the process method
        result_findings_list, result_input_core = self.handle_scan.process(
            dict_args, config_tool
        )

        # Assert the expected values
        self.assertEqual(result_findings_list, findings_list)
        self.assertEqual(result_input_core, input_core)
        self.secrets_manager_gateway.get_secret.assert_called_once_with(config_tool)
        mock_runner_engine_dependencies.assert_called_once_with(
            dict_args, config_tool, secret_tool, self.devops_platform_gateway
        )