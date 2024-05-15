import unittest
from unittest.mock import MagicMock
from unittest import mock
from devsecops_engine_tools.engine_core.src.domain.usecases.handle_risk import (
    HandleRisk,
)
from devsecops_engine_tools.engine_core.src.domain.model.customs_exceptions import (
    ExceptionGettingFindings,
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
    @mock.patch(
        "devsecops_engine_tools.engine_core.src.domain.usecases.handle_risk.HandleRisk.get_finding_list"
    )
    def test_process(self, mock_get_finding_list, mock_runner_engine_risk):
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
        mock_get_finding_list.assert_called_once
        mock_runner_engine_risk.assert_called_once

    def test_get_finding_list(self):
        dict_args = {
            "use_secrets_manager": "true",
            "tool": "engine_risk",
            "remote_config_repo": "test_repo",
        }
        secret_tool = None
        remote_config = {"ENGINE_RISK": {"ENABLED": "true"}}

        # Call the process method
        self.handle_risk.get_finding_list(
            dict_args,
            secret_tool,
            remote_config
        )

        # Assert the expected values
        self.vulnerability_management.get_all_findings.assert_called_once()
        self.devops_platform_gateway.get_variable.assert_called_with("pipeline_name")

    @mock.patch("devsecops_engine_tools.engine_core.src.domain.usecases.handle_risk.logger.error")
    def test_get_finding_list_exception(self, mock_logger_error):
        dict_args = {
            "use_secrets_manager": "true",
            "tool": "engine_risk",
            "remote_config_repo": "test_repo",
        }
        secret_tool = None
        remote_config = {"ENGINE_RISK": {"ENABLED": "true"}}
        self.vulnerability_management.get_all_findings.side_effect = ExceptionGettingFindings("error")

        # Call the process method
        self.handle_risk.get_finding_list(
            dict_args,
            secret_tool,
            remote_config
        )

        # Assert the expected values
        mock_logger_error.assert_called_with("Error getting finding list in handle risk: error")







    # @mock.patch("devsecops_engine_tools.engine_core.src.domain.usecases.handle_risk.logger.error")
    # def test_process_exception(self, mock_print):
    #     dict_args = {
    #         "use_secrets_manager": "true",
    #         "tool": "engine_risk",
    #         "remote_config_repo": "test_repo",
    #     }
    #     config_tool = {"ENGINE_RISK": {"ENABLED": "true"}}

    #     # Call the process method
    #     self.handle_risk.process(
    #         dict_args, config_tool
    #     )

    #     # Assert the expected values
    #     mock_print.assert_called
