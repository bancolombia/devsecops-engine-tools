import unittest
from unittest.mock import MagicMock, patch
from devsecops_engine_tools.engine_utilities.sonarqube.infrastructure.entry_points.entry_point_report_sonar import init_report_sonar

class TestInitReportSonar(unittest.TestCase):

    @patch(
        "devsecops_engine_tools.engine_utilities.sonarqube.infrastructure.entry_points.entry_point_report_sonar.ReportSonar"
    )
    def test_init_report_sonar_calls_process(self, mock_report_sonar):
        # Arrange
        mock_vulnerability_management_gateway = MagicMock()
        mock_vulnerability_send_gateway = MagicMock()
        mock_secrets_manager_gateway = MagicMock()
        mock_devops_platform_gateway = MagicMock()
        mock_sonar_gateway = MagicMock()
        args = {"remote_config_repo": "some_repo", "use_secrets_manager": "true"}

        # Act
        init_report_sonar(
            vulnerability_management_gateway=mock_vulnerability_management_gateway,
            vulnerability_send_report_gateway=mock_vulnerability_send_gateway,
            secrets_manager_gateway=mock_secrets_manager_gateway,
            devops_platform_gateway=mock_devops_platform_gateway,
            sonar_gateway=mock_sonar_gateway,
            args=args,
        )

        # Assert
        mock_report_sonar.assert_called_once_with(
            mock_vulnerability_management_gateway,
            mock_vulnerability_send_gateway,
            mock_secrets_manager_gateway,
            mock_devops_platform_gateway,
            mock_sonar_gateway,
        )
        mock_report_sonar.return_value.process.assert_called_once_with(args)