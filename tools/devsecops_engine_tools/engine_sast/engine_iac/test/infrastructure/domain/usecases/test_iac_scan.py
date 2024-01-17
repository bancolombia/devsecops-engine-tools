import unittest
from unittest.mock import MagicMock
from devsecops_engine_tools.engine_sast.engine_iac.src.domain.usecases.iac_scan import (
    IacScan,
)


class TestIacScan(unittest.TestCase):
    def setUp(self):
        self.tool_gateway = MagicMock()
        self.devops_platform_gateway = MagicMock()
        self.iac_scan = IacScan(self.tool_gateway, self.devops_platform_gateway)

    def test_process(self):
        dict_args = {"remote_config_repo": "example_repo", "environment": "test"}
        secret_tool = "example_secret"
        tool = "CHECKOV"

        # Mock the return values of the dependencies
        self.devops_platform_gateway.get_remote_config.return_value = {
            "CHECKOV": {
                "VERSION": "2.3.296",
                "SEARCH_PATTERN": ["AW", "NU"],
                "IGNORE_SEARCH_PATTERN": [
                    "test",
                ],
                "USE_EXTERNAL_CHECKS_GIT": "True",
                "EXTERNAL_CHECKS_GIT": "rules",
                "EXTERNAL_GIT_SSH_HOST": "github",
                "EXTERNAL_GIT_PUBLIC_KEY_FINGERPRINT": "fingerprint",
                "USE_EXTERNAL_CHECKS_DIR": "False",
                "EXTERNAL_DIR_OWNER": "test",
                "EXTERNAL_DIR_REPOSITORY": "repository",
                "EXTERNAL_DIR_ASSET_NAME": "rules",
                "EXCLUSIONS_PATH": "Exclusions.json",
                "MESSAGE_INFO_SAST_RM": "message test",
                "THRESHOLD": {
                    "VULNERABILITY": {
                        "Critical": 10,
                        "High": 3,
                        "Medium": 20,
                        "Low": 30,
                    },
                    "COMPLIANCE": {"Critical": 4},
                },
                "RULES": "",
            }
        }

        self.devops_platform_gateway.get_variable.return_value = "example_pipeline"

        self.tool_gateway.run_tool.return_value = (
            ["finding1", "finding2"],
            "/path/to/results",
        )

        findings_list, input_core = self.iac_scan.process(dict_args, secret_tool, tool)

        # Assert the expected return values
        self.assertEqual(findings_list, ["finding1", "finding2"])
        self.assertEqual(input_core.totalized_exclusions, [])
        self.assertEqual(input_core.threshold_defined.vulnerability.critical, 10)
        self.assertEqual(input_core.path_file_results, "/path/to/results")
        self.assertEqual(input_core.custom_message_break_build, "message test")
        self.assertEqual(input_core.scope_pipeline, "example_pipeline")
        self.assertEqual(input_core.stage_pipeline, "Release")


if __name__ == "__main__":
    unittest.main()
