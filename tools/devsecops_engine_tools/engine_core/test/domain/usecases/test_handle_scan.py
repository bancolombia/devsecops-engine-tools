import unittest
from unittest.mock import MagicMock
from unittest import mock
from devsecops_engine_tools.engine_core.src.domain.model.input_core import InputCore
from devsecops_engine_tools.engine_core.src.domain.model.threshold import Threshold
from devsecops_engine_tools.engine_core.src.domain.usecases.handle_scan import (
    HandleScan,
)


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

        # Mock the get_findings_risk_acceptance method
        self.vulnerability_management.get_findings_risk_acceptance = MagicMock()
        self.vulnerability_management.get_findings_risk_acceptance.return_value = []

        # Call the process method
        result_findings_list, result_input_core = self.handle_scan.process(
            dict_args, config_tool
        )

        # Assert the expected values
        self.assertEqual(result_findings_list, findings_list)
        self.assertEqual(result_input_core, input_core)
        self.secrets_manager_gateway.get_secret.assert_called_once_with(config_tool)
        mock_runner_engine_iac.assert_called_once_with(
            dict_args, config_tool["ENGINE_IAC"]["TOOL"], secret_tool
        )
        self.vulnerability_management.send_vulnerability_management.assert_called_once()
        self.vulnerability_management.get_findings_risk_acceptance.assert_called_once()

    @mock.patch(
        "devsecops_engine_tools.engine_core.src.domain.usecases.handle_scan.runner_engine_container"
    )
    def test_process_with_engine_container(self, mock_runner_engine_container):
        dict_args = {
            "use_secrets_manager": "true",
            "tool": "engine_container",
            "remote_config_repo": "test_repo",
        }
        config_tool = {"ENGINE_CONTAINER": "some_config"}
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
        mock_runner_engine_container.assert_called_once_with(
            dict_args, config_tool, secret_tool["token_prisma_cloud"]
        )

    @mock.patch("builtins.print")
    def test_process_with_engine_dast(self, mock_print):
        dict_args = {
            "use_secrets_manager": "false",
            "tool": "engine_dast",
        }
        config_tool = {"ENGINE_DAST": "some_config"}
        self.handle_scan.process(dict_args, config_tool)
        mock_print.assert_called_once_with("not yet enabled")

    @mock.patch("builtins.print")
    def test_process_with_engine_secret(self, mock_print):
        dict_args = {
            "use_secrets_manager": "false",
            "tool": "engine_secret",
        }
        config_tool = {"ENGINE_SECRET": "some_config"}
        self.handle_scan.process(dict_args, config_tool)
        mock_print.assert_called_once_with("not yet enabled")

    @mock.patch("builtins.print")
    def test_process_with_engine_dependencies(self, mock_print):
        dict_args = {
            "use_secrets_manager": "false",
            "tool": "engine_dependencies",
        }
        config_tool = {"ENGINE_DEPENDENCIES": "some_config"}
        self.handle_scan.process(dict_args, config_tool)
        mock_print.assert_called_once_with("not yet enabled")
