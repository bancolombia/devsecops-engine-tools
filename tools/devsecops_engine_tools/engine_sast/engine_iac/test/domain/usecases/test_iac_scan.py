import unittest
from datetime import datetime
from unittest.mock import MagicMock
from devsecops_engine_tools.engine_sast.engine_iac.src.domain.usecases.iac_scan import (
    IacScan,
)
from devsecops_engine_tools.engine_core.src.domain.model.finding import (
    Category,
    Finding,
)


class TestIacScan(unittest.TestCase):
    def setUp(self):
        self.tool_gateway = MagicMock()
        self.devops_platform_gateway = MagicMock()
        self.remote_config_source_gateway = MagicMock()
        self.iac_scan = IacScan(self.tool_gateway, self.devops_platform_gateway, self.remote_config_source_gateway)

    def side_effect(self, arg):
        if arg == "stage":
            return "Release"
        else:
            return "example_pipeline"

    def test_process(self):
        dict_args = {
            "remote_config_repo": "example_repo",
            "remote_config_branch": "",
            "folder_path": ".",
            "environment": "test",
            "platform": "cloudformation",
            "token_external_checks": "token",
            "context": "false",
        }
        secret_tool = "example_secret"
        tool = "CHECKOV"

        # Mock the return values of the dependencies
        self.remote_config_source_gateway.get_remote_config.return_value = {
            "SEARCH_PATTERN": ["AW", "NU"],
            "IGNORE_SEARCH_PATTERN": "(.*_test)",
            "EXCLUSIONS_PATH": "Exclusions.json",
            "MESSAGE_INFO_ENGINE_IAC": "message test",
            "UPDATE_SERVICE_WITH_FILE_NAME_CFT": "True",
            "REGEX_CLEAN_END_PIPELINE_NAME": "^(.*?)(?:_(DEV|CER|PDN))$",
            "THRESHOLD": {
                "VULNERABILITY": {
                    "Critical": 10,
                    "High": 3,
                    "Medium": 20,
                    "Low": 30,
                },
                "COMPLIANCE": {"Critical": 4},
                "PRIORITY": {
                    "Very Critical": 1,
                    "Critical": 3,
                    "High": 5,
                    "Medium Low": 15
                }
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
            "remote_config_branch": "",
            "folder_path": "example_folder",
            "environment": "test",
            "platform": "eks",
            "token_external_checks": "token",
        }
        secret_tool = "example_secret"
        tool = "CHECKOV"

        self.remote_config_source_gateway.get_remote_config.side_effect = [
            # Resultado para el primer llamado (init_config_tool)
            {
                "SEARCH_PATTERN": ["AW", "NU"],
                "IGNORE_SEARCH_PATTERN": "(.*example_pipeline)",
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
                    "PRIORITY": {
                        "Very Critical": 1,
                        "Critical": 3,
                        "High": 5,
                        "Medium Low": 15
                    }
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

    def test_process_skip_search_folder_by_pattern_search(self):
        dict_args = {
            "remote_config_repo": "example_repo",
            "remote_config_branch": "",
            "folder_path": "example_folder",
            "environment": "test",
            "platform": "eks",
            "token_external_checks": "token",
        }
        secret_tool = "example_secret"
        tool = "CHECKOV"

        self.remote_config_source_gateway.get_remote_config.side_effect = [
            {
                "SEARCH_PATTERN": ["AW", "NU"],
                "IGNORE_SEARCH_PATTERN": "(.*_test)",
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
                    "PRIORITY": {
                        "Very Critical": 1,
                        "Critical": 3,
                        "High": 5,
                        "Medium Low": 15,
                    },
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
                "BY_PATTERN_SEARCH": {
                    ".*example_pipeline": {
                        "THRESHOLD": {
                            "VULNERABILITY": {
                                "Critical": 1,
                                "High": 2,
                                "Medium": 3,
                                "Low": 4,
                            },
                            "COMPLIANCE": {"Critical": 1},
                            "PRIORITY": {
                                "Very Critical": 1,
                                "Critical": 1,
                                "High": 1,
                                "Medium Low": 1,
                            },
                        },
                        "SKIP_TOOL": {
                            "create_date": "24012024",
                            "expired_date": "30012024",
                            "hu": "3423213",
                        },
                        "CHECKOV": [
                            {
                                "id": "CKV_K8S_9",
                                "where": "deployment-configmap.yaml",
                                "create_date": "18112023",
                                "expired_date": "18032024",
                                "severity": "HIGH",
                                "hu": "4338704",
                            }
                        ],
                    }
                },
            },
        ]

        self.devops_platform_gateway.get_variable.return_value = "example_pipeline"
        self.tool_gateway.run_tool.return_value = ([], None)

        findings_list, input_core = self.iac_scan.process(dict_args, secret_tool, tool, "qa")

        self.assertEqual(findings_list, [])
        self.assertEqual(len(input_core.totalized_exclusions), 2)
        self.assertEqual(input_core.totalized_exclusions[0].id, "CKV_K8S_8")
        self.assertEqual(input_core.totalized_exclusions[1].id, "CKV_K8S_9")
        self.tool_gateway.run_tool.assert_not_called()

    def _finding(self, check_id, severity, where="deployment.yaml: resource"):
        return Finding(
            id=check_id,
            cvss=None,
            where=where,
            description="description",
            severity=severity,
            identification_date="19012024",
            published_date_cve=None,
            module="engine_iac",
            category=Category.VULNERABILITY,
            requirements="guideline",
            tool="Checkov",
        )

    def test_build_excepted_checks_exclusions(self):
        findings_list = [
            self._finding("CKV_AWS_18", "medium"),
            self._finding("CKV_AWS_18", "high", where="other.yaml: resource"),
            self._finding("CKV_AWS_21", "low"),
            self._finding("CKV_AWS_99", "critical"),
        ]

        exclusions = self.iac_scan._build_excepted_checks_exclusions(
            {"excepted_checks": " CKV_AWS_18 , CKV_AWS_21 ,, CKV_AWS_404 "},
            findings_list,
        )

        self.assertEqual(
            [(e.id, e.severity, e.where, e.reason) for e in exclusions],
            [
                ("CKV_AWS_18", "high", "all", IacScan.EXCEPTED_CHECKS_REASON),
                ("CKV_AWS_18", "medium", "all", IacScan.EXCEPTED_CHECKS_REASON),
                ("CKV_AWS_21", "low", "all", IacScan.EXCEPTED_CHECKS_REASON),
            ],
        )
        # create_date must be set so the exclusions table can be rendered
        today = datetime.now().strftime("%d%m%Y")
        for exclusion in exclusions:
            self.assertEqual(exclusion.create_date, today)
            self.assertEqual(exclusion.expired_date, "")

    def test_build_excepted_checks_exclusions_without_flag(self):
        findings_list = [self._finding("CKV_AWS_18", "medium")]

        self.assertEqual(self.iac_scan._build_excepted_checks_exclusions({}, findings_list), [])
        self.assertEqual(
            self.iac_scan._build_excepted_checks_exclusions({"excepted_checks": ""}, findings_list),
            [],
        )
        self.assertEqual(
            self.iac_scan._build_excepted_checks_exclusions(
                {"excepted_checks": None}, findings_list
            ),
            [],
        )

    def test_process_with_excepted_checks(self):
        dict_args = {
            "remote_config_repo": "example_repo",
            "remote_config_branch": "",
            "folder_path": ".",
            "environment": "test",
            "platform": "cloudformation",
            "token_external_checks": "token",
            "context": "false",
            "excepted_checks": "CKV_AWS_18",
        }

        self.remote_config_source_gateway.get_remote_config.return_value = {
            "SEARCH_PATTERN": ["AW", "NU"],
            "IGNORE_SEARCH_PATTERN": "(.*_test)",
            "EXCLUSIONS_PATH": "Exclusions.json",
            "MESSAGE_INFO_ENGINE_IAC": "message test",
            "UPDATE_SERVICE_WITH_FILE_NAME_CFT": "False",
            "THRESHOLD": {
                "VULNERABILITY": {"Critical": 10, "High": 3, "Medium": 20, "Low": 30},
                "COMPLIANCE": {"Critical": 4},
                "PRIORITY": {"Very Critical": 1, "Critical": 3, "High": 5, "Medium Low": 15},
            },
            "CHECKOV": {"VERSION": "2.3.296", "RULES": ""},
        }
        self.devops_platform_gateway.get_variable.side_effect = self.side_effect

        findings = [
            self._finding("CKV_AWS_18", "medium"),
            self._finding("CKV_AWS_99", "high"),
        ]
        self.tool_gateway.run_tool.return_value = (findings, "/path/to/results")

        findings_list, input_core = self.iac_scan.process(dict_args, "secret", "CHECKOV", "pdn")

        self.assertEqual(findings_list, findings)
        self.assertEqual(len(input_core.totalized_exclusions), 1)
        self.assertEqual(input_core.totalized_exclusions[0].id, "CKV_AWS_18")
        self.assertEqual(input_core.totalized_exclusions[0].severity, "medium")
        self.assertEqual(input_core.totalized_exclusions[0].where, "all")
