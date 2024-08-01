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

    def side_effect(self, arg):
        if arg == "stage":
            return "Release"
        else:
            return "example_pipeline"

    def test_process(self):
        dict_args = {
            "remote_config_repo": "example_repo",
            "folder_path": ".",
            "environment": "test",
            "platform": "cloudformation",
        }
        secret_tool = "example_secret"
        tool = "CHECKOV"

        # Mock the return values of the dependencies
        self.devops_platform_gateway.get_remote_config.return_value = {
            "SEARCH_PATTERN": ["AW", "NU"],
            "IGNORE_SEARCH_PATTERN": [
                "test",
            ],
            "EXCLUSIONS_PATH": "Exclusions.json",
            "MESSAGE_INFO_ENGINE_IAC": "message test",
            "UPDATE_SERVICE_WITH_FILE_NAME_CFT": "True",
            "THRESHOLD": {
                "VULNERABILITY": {
                    "Critical": 10,
                    "High": 3,
                    "Medium": 20,
                    "Low": 30,
                },
                "COMPLIANCE": {"Critical": 4},
            },
            "CHECKOV": {
                "VERSION": "2.3.296",
                "USE_EXTERNAL_CHECKS_GIT": "True",
                "EXTERNAL_CHECKS_GIT": "rules",
                "EXTERNAL_GIT_SSH_HOST": "github",
                "EXTERNAL_GIT_PUBLIC_KEY_FINGERPRINT": "fingerprint",
                "USE_EXTERNAL_CHECKS_DIR": "False",
                "EXTERNAL_DIR_OWNER": "test",
                "EXTERNAL_DIR_REPOSITORY": "repository",
                "RULES": "",
            },
        }

        # self.devops_platform_gateway.get_variable.return_value = "example_pipeline"
        self.devops_platform_gateway.get_variable.side_effect = self.side_effect

        self.tool_gateway.run_tool.return_value = (
            ["finding1", "finding2"],
            "/path/to/results",
        )

        findings_list, input_core = self.iac_scan.process(dict_args, secret_tool, tool, "pdn")

        # Assert the expected return values
        self.assertEqual(findings_list, ["finding1", "finding2"])
        self.assertEqual(input_core.totalized_exclusions, [])
        self.assertEqual(input_core.threshold_defined.vulnerability.critical, 10)
        self.assertEqual(input_core.path_file_results, "/path/to/results")
        self.assertEqual(input_core.custom_message_break_build, "message test")
        self.assertEqual(input_core.stage_pipeline, "Release")

    def test_process_skip_search_folder(self):
        dict_args = {
            "remote_config_repo": "example_repo",
            "folder_path": "example_folder",
            "environment": "test",
            "platform": "eks",
        }
        secret_tool = "example_secret"
        tool = "CHECKOV"

        self.devops_platform_gateway.get_remote_config.side_effect = [
            # Resultado para el primer llamado (init_config_tool)
            {
                "SEARCH_PATTERN": ["AW", "NU"],
                "IGNORE_SEARCH_PATTERN": [
                    "test",
                ],
                "EXCLUSIONS_PATH": "Exclusions.json",
                "MESSAGE_INFO_ENGINE_IAC": "message test",
                "UPDATE_SERVICE_WITH_FILE_NAME_CFT": "false",
                "THRESHOLD": {
                    "VULNERABILITY": {
                        "Critical": 10,
                        "High": 3,
                        "Medium": 20,
                        "Low": 30,
                    },
                    "COMPLIANCE": {"Critical": 4},
                },
                "CHECKOV": {
                    "VERSION": "2.3.296",
                    "USE_EXTERNAL_CHECKS_GIT": "True",
                    "EXTERNAL_CHECKS_GIT": "rules",
                    "EXTERNAL_GIT_SSH_HOST": "github",
                    "EXTERNAL_GIT_PUBLIC_KEY_FINGERPRINT": "fingerprint",
                    "USE_EXTERNAL_CHECKS_DIR": "False",
                    "EXTERNAL_DIR_OWNER": "test",
                    "EXTERNAL_DIR_REPOSITORY": "repository",
                    "RULES": "",
                },
            },
            # Resultado para el segundo llamado (exclusions)
            {
                "All": {
                    "CHECKOV": [
                        {
                            "id": "CKV_K8S_8",
                            "where": "all",
                            "create_date": "18112023",
                            "expired_date": "18032024",
                            "severity": "HIGH",
                            "hu": "4338704",
                        }
                    ]
                },
                "example_pipeline": {
                    "SKIP_TOOL": {
                        "create_date": "24012024",
                        "expired_date": "30012024",
                        "hu": "3423213",
                    },
                    "CHECKOV": [
                        {
                            "id": "CKV_K8S_8",
                            "where": "deployment-configmap.yaml",
                            "create_date": "18112023",
                            "expired_date": "18032024",
                            "severity": "HIGH",
                            "hu": "4338704",
                            "pipeline": "true",
                        }
                    ],
                },
            },
        ]

        self.devops_platform_gateway.get_variable.return_value = "example_pipeline"

        findings_list, input_core = self.iac_scan.process(dict_args, secret_tool, tool, "qa")

        # Assert the expected return values
        self.assertEqual(findings_list, [])
        self.assertIsNotNone(input_core)
