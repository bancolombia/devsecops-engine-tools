import unittest
from unittest import mock
from unittest.mock import MagicMock, patch
from devsecops_engine_tools.engine_utilities.sonarqube.domain.usecases.report_sonar import (
    ReportSonar
)

class TestReportSonar(unittest.TestCase):

    @patch(
        "devsecops_engine_tools.engine_utilities.sonarqube.domain.usecases.report_sonar.invalid_pipeline"
    )
    @patch(
        "devsecops_engine_tools.engine_utilities.sonarqube.domain.usecases.report_sonar.invalid_branch"
    )
    def test_process_skipped_by_policy(self, mock_invalid_branch, mock_invalid_pipeline):
        # Arrange
        mock_vulnerability_gateway = MagicMock()
        mock_secrets_manager_gateway = MagicMock()
        mock_devops_platform_gateway = MagicMock()
        mock_sonar_gateway = MagicMock()
        mock_invalid_pipeline.return_value = True
        mock_invalid_branch.return_value = False
        report_sonar = ReportSonar(
            vulnerability_management_gateway=mock_vulnerability_gateway,
            secrets_manager_gateway=mock_secrets_manager_gateway,
            devops_platform_gateway=mock_devops_platform_gateway,
            sonar_gateway=mock_sonar_gateway,
        )
        args = {"remote_config_repo": "some_repo", "use_secrets_manager": "true"}

        # Act
        report_sonar.process(args)

        # Assert
        mock_devops_platform_gateway.result_pipeline.assert_called_once_with("succeeded")
        mock_vulnerability_gateway.send_report.assert_not_called()

    @patch(
        "devsecops_engine_tools.engine_utilities.sonarqube.domain.usecases.report_sonar.set_repository"
    )
    @patch(
        "devsecops_engine_tools.engine_utilities.sonarqube.domain.usecases.report_sonar.set_environment"
    )
    @patch(
        "devsecops_engine_tools.engine_utilities.sonarqube.domain.usecases.report_sonar.invalid_pipeline"
    )
    @patch(
        "devsecops_engine_tools.engine_utilities.sonarqube.domain.usecases.report_sonar.invalid_branch"
    )
    def test_process_with_secrets_manager(self, mock_invalid_branch, mock_invalid_pipeline, mock_set_environment, mock_set_repository):
        # Arrange
        mock_vulnerability_gateway = MagicMock()
        mock_secrets_manager_gateway = MagicMock()
        mock_devops_platform_gateway = MagicMock()
        mock_sonar_gateway = MagicMock()
        mock_invalid_pipeline.return_value = False
        mock_invalid_branch.return_value = False
        mock_devops_platform_gateway.get_variable.side_effect = ["pipeline_name", "branch_name", "repository"]
        mock_secrets_manager_gateway.get_secret.return_value = {
            "token_defect_dojo": "dojo_token",
            "token_cmdb": "cmdb_token"
        }
        mock_sonar_gateway.get_project_keys.return_value = ["project_key_1"]
        report_sonar = ReportSonar(
            vulnerability_management_gateway=mock_vulnerability_gateway,
            secrets_manager_gateway=mock_secrets_manager_gateway,
            devops_platform_gateway=mock_devops_platform_gateway,
            sonar_gateway=mock_sonar_gateway,
        )
        args = {"remote_config_repo": "some_repo", "use_secrets_manager": "true"}

        # Act
        report_sonar.process(args)

        # Assert
        mock_secrets_manager_gateway.get_secret.assert_called_once()
        mock_vulnerability_gateway.send_report.assert_called_with(
            mock.ANY,
            mock_set_repository.return_value,
            mock_set_environment.return_value, 
            "dojo_token",
            "cmdb_token",
            mock.ANY,
            mock_devops_platform_gateway,
            "project_key_1" 
        )

    @patch(
        "devsecops_engine_tools.engine_utilities.sonarqube.domain.usecases.report_sonar.invalid_pipeline"
    )
    @patch(
        "devsecops_engine_tools.engine_utilities.sonarqube.domain.usecases.report_sonar.invalid_branch"
    )
    def test_process_without_secrets_manager(self, mock_invalid_branch, mock_invalid_pipeline):
        # Arrange
        mock_vulnerability_gateway = MagicMock()
        mock_secrets_manager_gateway = MagicMock()
        mock_devops_platform_gateway = MagicMock()
        mock_sonar_gateway = MagicMock()
        mock_invalid_pipeline.return_value = False
        mock_invalid_branch.return_value = False
        mock_devops_platform_gateway.get_variable.side_effect = ["pipeline_name", "branch_name", "repository"]
        mock_sonar_gateway.get_project_keys.return_value = ["project_key_1"]
        report_sonar = ReportSonar(
            vulnerability_management_gateway=mock_vulnerability_gateway,
            secrets_manager_gateway=mock_secrets_manager_gateway,
            devops_platform_gateway=mock_devops_platform_gateway,
            sonar_gateway=mock_sonar_gateway,
        )
        args = {
            "remote_config_repo": "some_repo", 
            "use_secrets_manager": "false", 
            "token_defect_dojo": "dojo_token", 
            "token_cmdb": "cmdb_token"
        }

        # Act
        report_sonar.process(args)

        # Assert
        mock_secrets_manager_gateway.get_secret.assert_not_called()
        mock_vulnerability_gateway.send_report.assert_called_once_with(
            mock.ANY,
            mock.ANY, 
            mock.ANY,
            "dojo_token",
            "cmdb_token",
            mock.ANY,
            mock_devops_platform_gateway, 
            "project_key_1"
        )