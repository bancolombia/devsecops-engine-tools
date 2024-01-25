import unittest
from unittest import mock
from devsecops_engine_tools.engine_core.src.infrastructure.entry_points.entry_point_core import (
    get_inputs_from_cli,
    init_engine_core,
)


class TestEntryPointCore(unittest.TestCase):
    @mock.patch("argparse.ArgumentParser.parse_args")
    def test_get_inputs_from_cli(self, mock_parse_args):
        # Set up mock arguments
        mock_args = mock.Mock(
            remote_config_repo="https://github.com/example/repo",
            tool="engine_iac",
            environment="dev",
            platform="eks",
            use_secrets_manager="true",
            use_vulnerability_management="false",
            token_cmdb="abc123",
            token_vulnerability_management=None,
            token_engine_container=None,
        )
        mock_parse_args.return_value = mock_args

        # Call the function
        result = get_inputs_from_cli([])

        # Assert that the function returns the expected result
        expected_result = {
            "remote_config_repo": "https://github.com/example/repo",
            "tool": "engine_iac",
            "environment": "dev",
            "platform": "eks",
            "use_secrets_manager": "true",
            "use_vulnerability_management": "false",
            "token_cmdb": "abc123",
            "token_vulnerability_management": None,
            "token_engine_container": None,
        }
        self.assertEqual(result, expected_result)

    @mock.patch(
        "devsecops_engine_tools.engine_core.src.infrastructure.entry_points.entry_point_core.get_inputs_from_cli"
    )
    @mock.patch(
        "devsecops_engine_tools.engine_core.src.infrastructure.entry_points.entry_point_core.HandleScan"
    )
    @mock.patch(
        "devsecops_engine_tools.engine_core.src.infrastructure.entry_points.entry_point_core.BreakBuild"
    )
    @mock.patch(
        "devsecops_engine_tools.engine_core.src.infrastructure.entry_points.entry_point_core.MetricsManager"
    )
    def test_init_engine_core(
        self,
        mock_metrics_manager,
        mock_break_build,
        mock_handle_scan,
        mock_get_inputs_from_cli,
    ):
        # Set up mock arguments
        mock_args = {
            "remote_config_repo": "https://github.com/example/repo",
            "tool": "engine_iac",
            "environment": "dev",
            "platform": "eks",
            "use_secrets_manager": "true",
            "use_vulnerability_management": "false",
            "token_cmdb": "abc123",
            "token_vulnerability_management": None,
            "token_engine_container": None,
        }

        mock_config_tool = {
            "METRICS_MANAGER": {"ENABLED": "true"},
            "ENGINE_IAC": {"ENABLED": "true", "TOOL": "tool"}
        }
        mock_findings_list = []
        mock_input_core = {}
        mock_scan_result = {}

        mock_get_inputs_from_cli.return_value = mock_args
        mock_devops_platform_gateway = mock.Mock()

        mock_devops_platform_gateway.get_remote_config.return_value = mock_config_tool

        mock_handle_scan.return_value.process.return_value = (
            mock_findings_list,
            mock_input_core,
        )

        mock_break_build.return_value.process.return_value = mock_scan_result

        # Call the function
        init_engine_core(
            vulnerability_management_gateway=mock.Mock(),
            secrets_manager_gateway=mock.Mock(),
            devops_platform_gateway=mock_devops_platform_gateway,
            print_table_gateway=mock.Mock(),
            metrics_manager_gateway=mock.Mock(),
        )

        # Assert that the function calls were made with the expected arguments
        mock_devops_platform_gateway.get_remote_config.assert_called_once_with(
            "https://github.com/example/repo", "/resources/ConfigTool.json"
        )
        mock_handle_scan.return_value.process.assert_called_once_with(
            mock_args, mock_config_tool
        )
        mock_break_build.return_value.process.assert_called_once_with(
            mock_findings_list, mock_input_core
        )
        mock_metrics_manager.return_value.process.assert_called_once_with(
            mock_config_tool, mock_input_core, mock_args, mock_scan_result
        )

    @mock.patch("builtins.print")
    @mock.patch(
        "devsecops_engine_tools.engine_core.src.infrastructure.entry_points.entry_point_core.get_inputs_from_cli"
    )
    def test_init_engine_core_disabled(self, mock_get_inputs_from_cli ,mock_print):
        # Set up mock arguments
        mock_args = {
            "remote_config_repo": "https://github.com/example/repo",
            "tool": "engine_iac",
            "environment": "dev",
            "platform": "eks",
            "use_secrets_manager": "false",
            "use_vulnerability_management": "false"
        }

        mock_get_inputs_from_cli.return_value = mock_args

        mock_config_tool = {
            "METRICS_MANAGER": {"ENABLED": "true"},
            "ENGINE_IAC": {"ENABLED": "false", "TOOL": "tool"}
        }
        mock_devops_platform_gateway = mock.Mock()

        mock_devops_platform_gateway.get_remote_config.return_value = mock_config_tool

        # Call the function
        init_engine_core(
            vulnerability_management_gateway=mock.Mock(),
            secrets_manager_gateway=mock.Mock(),
            devops_platform_gateway=mock_devops_platform_gateway,
            print_table_gateway=mock.Mock(),
            metrics_manager_gateway=mock.Mock(),
        )

        # Assert
        assert mock_print.called


