import unittest
from unittest.mock import MagicMock
from unittest import mock
from devsecops_engine_tools.engine_core.src.domain.usecases.handle_risk import (
    HandleRisk,
)

class TestHandleRisk(unittest.TestCase):
    def setUp(self):
        self.vulnerability_management = MagicMock()
        self.secrets_manager_gateway = MagicMock()
        self.devops_platform_gateway = MagicMock()
        self.print_table_gateway = MagicMock()
        self.handle_risk = HandleRisk(
            self.vulnerability_management,
            self.secrets_manager_gateway,
            self.devops_platform_gateway,
            self.print_table_gateway
        )

    @mock.patch(
        "devsecops_engine_tools.engine_core.src.domain.usecases.handle_risk.runner_engine_risk"
    )
    def test_process(self, mock_runner_engine_risk):
        dict_args = {
            "use_secrets_manager": "true",
            "tool": "engine_risk",
            "remote_config_repo": "test_repo",
        }
        config_tool = {"ENGINE_RISK": {"ENABLED": "true"}}

        # Call the process method
        self.handle_risk.process(
            dict_args, config_tool
        )

        # Assert the expected values
        mock_runner_engine_risk.assert_called_once

    @mock.patch("builtins.print")
    def test_process_exception(self, mock_print):
        dict_args = {
            "use_secrets_manager": "true",
            "tool": "engine_risk",
            "remote_config_repo": "test_repo",
        }
        config_tool = {"ENGINE_RISK": {"ENABLED": "true"}}

        # Call the process method
        self.handle_risk.process(
            dict_args, config_tool
        )

        # Assert the expected values
        mock_print.assert_called
