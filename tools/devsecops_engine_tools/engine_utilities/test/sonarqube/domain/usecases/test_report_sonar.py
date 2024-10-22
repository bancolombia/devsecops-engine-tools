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
        mock_vulnerability_send_gateway = MagicMock()
        mock_secrets_manager_gateway = MagicMock()
        mock_devops_platform_gateway = MagicMock()
        mock_sonar_gateway = MagicMock()
        mock_invalid_pipeline.return_value = True
        mock_invalid_branch.return_value = False
        report_sonar = ReportSonar(
            vulnerability_management_gateway=mock_vulnerability_gateway,
            vulnerability_send_report_gateway=mock_vulnerability_send_gateway,
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
    def test_process_valid(
        self, mock_invalid_branch, mock_invalid_pipeline, 
        mock_set_environment, mock_set_repository
    ):
        # Arrange
        mock_vulnerability_gateway = MagicMock()
        mock_vulnerability_send_gateway = MagicMock()
        mock_secrets_manager_gateway = MagicMock()
        mock_devops_platform_gateway = MagicMock()
        mock_sonar_gateway = MagicMock()

        mock_invalid_pipeline.return_value = False
        mock_invalid_branch.return_value = False
        mock_devops_platform_gateway.get_variable.side_effect = [
            "pipeline_name",
            "branch_name",
            "repository"
        ]
        mock_devops_platform_gateway.get_source_code_management_uri.return_value = "repository_uri"
        mock_set_environment.return_value = "environment_name"
        mock_secrets_manager_gateway.get_secret.return_value = {
            "token_sonar": "sonar_token"
        }
        
        mock_sonar_gateway.get_project_keys.return_value = ["project_key_1"]
        mock_sonar_gateway.filter_by_sonarqube_tag.return_value = [
            MagicMock(unique_id_from_tool="123", active=True, mitigated=False, false_p=False)
        ]
        mock_sonar_gateway.get_vulnerabilities.return_value = [
            {"status": "RESOLVED", "id": "123"}
        ]
        mock_sonar_gateway.find_issue_by_id.return_value = {
            "status": "RESOLVED", "id": "123"
        }

        report_sonar = ReportSonar(
            vulnerability_management_gateway=mock_vulnerability_gateway,
            vulnerability_send_report_gateway=mock_vulnerability_send_gateway,
            secrets_manager_gateway=mock_secrets_manager_gateway,
            devops_platform_gateway=mock_devops_platform_gateway,
            sonar_gateway=mock_sonar_gateway,
        )

        args = {"remote_config_repo": "repo", "use_secrets_manager": "true", "sonar_url": "sonar_url"}

        # Act
        report_sonar.process(args)

        # Assert
        mock_sonar_gateway.get_vulnerabilities.assert_called_once_with(
            "sonar_url", "sonar_token", "project_key_1"
        )
        mock_sonar_gateway.change_issue_transition.assert_called_once_with(
            "sonar_url", "sonar_token", "123", "reopen"
        )
        mock_vulnerability_send_gateway.send_report.assert_called_once_with(
            mock.ANY,
            "repository_uri",
            "environment_name",
            {"token_sonar": "sonar_token"},
            mock.ANY,
            mock_devops_platform_gateway,
            "project_key_1"
        )