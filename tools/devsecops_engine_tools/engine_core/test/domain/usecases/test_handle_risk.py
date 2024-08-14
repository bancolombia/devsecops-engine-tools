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
            self.print_table_gateway,
        )

    @mock.patch(
        "devsecops_engine_tools.engine_core.src.domain.usecases.handle_risk.runner_engine_risk"
    )
    @mock.patch(
        "devsecops_engine_tools.engine_core.src.domain.usecases.handle_risk.HandleRisk._get_finding_list"
    )
    def test_process(self, mock_get_finding_list, mock_runner_engine_risk):
        dict_args = {
            "use_secrets_manager": "true",
            "tool": "engine_risk",
            "remote_config_repo": "test_repo",
        }
        config_tool = {"ENGINE_RISK": {"ENABLED": "true"}}
        self.devops_platform_gateway.get_remote_config.return_value = {
            "PARENT_ANALYSIS": {"ENABLED": "true", "PARENT_IDENTIFIER": "id"},
        }
        self.devops_platform_gateway.get_variable.return_value = "pipeline_name_id_test"

        # Call the process method
        self.handle_risk.process(dict_args, config_tool)

        # Assert the expected values
        assert mock_get_finding_list.call_count == 2
        assert mock_runner_engine_risk.call_count == 2

    def test_get_finding_list(self):
        dict_args = {
            "use_secrets_manager": "true",
            "tool": "engine_risk",
            "remote_config_repo": "test_repo",
        }
        secret_tool = None
        remote_config = {"ENGINE_RISK": {"ENABLED": "true"}}
        service = "pipeline_name_id_test"

        # Call the process method
        self.handle_risk._get_finding_list(
            dict_args, secret_tool, remote_config, service
        )

        # Assert the expected values
        self.vulnerability_management.get_all_findings.assert_called_once()

    @mock.patch(
        "devsecops_engine_tools.engine_core.src.domain.usecases.handle_risk.logger.error"
    )
    def test_get_finding_list_exception(self, mock_logger_error):
        dict_args = {
            "use_secrets_manager": "true",
            "tool": "engine_risk",
            "remote_config_repo": "test_repo",
        }
        secret_tool = None
        remote_config = {"ENGINE_RISK": {"ENABLED": "true"}}
        service = "pipeline_name_id_test"
        self.vulnerability_management.get_all_findings.side_effect = (
            ExceptionGettingFindings("error")
        )

        # Call the process method
        self.handle_risk._get_finding_list(
            dict_args, secret_tool, remote_config, service
        )

        # Assert the expected values
        mock_logger_error.assert_called_with(
            "Error getting finding list in handle risk: error"
        )
