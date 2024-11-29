import unittest
from unittest import mock
from unittest.mock import MagicMock, patch, call
from devsecops_engine_tools.engine_utilities.sonarqube.src.domain.usecases.report_sonar import (
    ReportSonar
)

class TestReportSonar(unittest.TestCase):
    @patch(
        "devsecops_engine_tools.engine_utilities.sonarqube.src.domain.usecases.report_sonar.set_repository"
    )
    @patch(
        "devsecops_engine_tools.engine_utilities.sonarqube.src.domain.usecases.report_sonar.define_env"
    )
    def test_process_valid(
        self, mock_define_env, mock_set_repository
    ):
        # Arrange
        mock_vulnerability_gateway = MagicMock()
        mock_secrets_manager_gateway = MagicMock()
        mock_devops_platform_gateway = MagicMock()
        mock_sonar_gateway = MagicMock()

        mock_devops_platform_gateway.get_variable.side_effect = [
            "pipeline_name",
            "branch_name",
            "repository",
            "access_token",
            "build_execution_id",
            "build_id",
            "commit_hash"
        ]
        mock_set_repository.return_value = "repository_uri"
        mock_define_env.return_value = "dev"
        mock_secrets_manager_gateway.get_secret.return_value = {
            "token_sonar": "sonar_token"
        }

        mock_devops_platform_gateway.get_remote_config.return_value = {
            "PIPELINE_COMPONENTS": {},
            "SCOPE_VALIDATION_REGEX": ""
        }
        
        mock_sonar_gateway.get_project_keys.return_value = ["project_key_1"]
        mock_sonar_gateway.filter_by_sonarqube_tag.return_value = [
            MagicMock(unique_id_from_tool="123", active=True, mitigated=False, false_p=False),
            MagicMock(unique_id_from_tool="1234", active=False, mitigated=False, false_p=True)
        ]
        mock_sonar_gateway.search_finding_by_id.side_effect = [
            {"status": "RESOLVED", "key": "123", "type": "VULNERABILITY"},
            {"status": "REVIEWED", "key": "1234"}
        ]

        report_sonar = ReportSonar(
            vulnerability_management_gateway=mock_vulnerability_gateway,
            secrets_manager_gateway=mock_secrets_manager_gateway,
            devops_platform_gateway=mock_devops_platform_gateway,
            sonar_gateway=mock_sonar_gateway,
        )

        args = {"remote_config_repo": "repo", "use_secrets_manager": "true", "sonar_url": "sonar_url", "remote_config_branch": ""}

        # Act
        report_sonar.process(args)

        # Assert
        mock_sonar_gateway.get_findings.assert_has_calls(
            [
                call("sonar_url", 
                    "sonar_token", 
                    "/api/issues/search",
                    {
                        "componentKeys": "project_key_1",
                        "types": "VULNERABILITY",
                        "ps": 500,
                        "p": 1,
                        "s": "CREATION_DATE",
                        "asc": "false"
                    },
                    "issues"
                ),
                call("sonar_url", 
                    "sonar_token", 
                    "/api/hotspots/search",
                    {
                        "projectKey": "project_key_1",
                        "ps": 100,
                        "p": 1
                    },
                    "hotspots"
                )
            ],
            any_order=False
        )
        mock_sonar_gateway.change_finding_status.assert_has_calls(
            [
                call(
                    "sonar_url", 
                    "sonar_token", 
                    "/api/issues/do_transition", 
                    {
                        "issue": "123",
                        "transition": "reopen"
                    },
                    "issue"
                )
            ],
            any_order=False
        )