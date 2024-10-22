import unittest
from unittest.mock import patch
import sys
import argparse
from devsecops_engine_tools.engine_utilities.sonarqube.applications.runner_report_sonar import runner_report_sonar, get_inputs_from_cli

class TestRunnerReportSonar(unittest.TestCase):
    # @patch(
    #     "devsecops_engine_tools.engine_utilities.sonarqube.applications.runner_report_sonar.get_inputs_from_cli"
    # )
    # @patch(
    #     "devsecops_engine_tools.engine_utilities.sonarqube.applications.runner_report_sonar.init_report_sonar"
    # )
    # def test_runner_report_sonar_success(self, mock_init_report_sonar, mock_get_inputs_from_cli):
    #     # Act
    #     runner_report_sonar()

    #     # Assert
    #     mock_init_report_sonar.assert_called_once()

    @patch(
        "devsecops_engine_tools.engine_utilities.sonarqube.applications.runner_report_sonar.get_inputs_from_cli"
    )
    @patch(
        "devsecops_engine_tools.engine_utilities.sonarqube.applications.runner_report_sonar.logger"
    )
    def test_runner_report_sonar_exception(self, mock_logger, mock_get_inputs_from_cli):
        # Arrange
        mock_get_inputs_from_cli.side_effect = Exception("Test exception")
        
        # Act
        runner_report_sonar()

        # Assert
        mock_logger.error.assert_called_with("Error report_sonar: Test exception ")

    @patch(
        "argparse.ArgumentParser.parse_args"
    )
    def test_get_inputs_from_cli(self, mock_parse_args):
        # Arrange
        mock_parse_args.return_value = argparse.Namespace(
            remote_config_repo="test_repo",
            use_secrets_manager="false",
            sonar_url="https://sonar.com/",
            token_cmdb="my_token_cmdb",
            token_vulnerability_management="my_token_vm",
            token_sonar="my_token_sonar",
        )

        expected_output = {
            "remote_config_repo": "test_repo",
            "use_secrets_manager": "false",
            "sonar_url": "https://sonar.com/",
            "token_cmdb": "my_token_cmdb",
            "token_vulnerability_management": "my_token_vm",
            "token_sonar": "my_token_sonar",
        }

        # Act
        result = get_inputs_from_cli(sys.argv[1:])
 
        # Assert
        self.assertEqual(result, expected_output)