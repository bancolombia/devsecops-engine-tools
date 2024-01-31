import unittest
from unittest.mock import MagicMock
from devsecops_engine_tools.engine_sast.engine_secret.src.domain.usecases.secret_scan import (
    SecretScan,
)


class TestSecretScan(unittest.TestCase):
    def setUp(self):
        self.tool_gateway = MagicMock()
        self.devops_platform_gateway = MagicMock()
        self.tool_deserialize = MagicMock()
        self.secret_scan = SecretScan(self.tool_gateway, self.devops_platform_gateway, self.tool_deserialize)

    def test_process(self):
        dict_args = {
            "remote_config_repo": "example_repo",
        }
        tool = "TRUFFLEHOG"

        # Mock the return values of the dependencies
        self.devops_platform_gateway.get_remote_config.return_value = {
            "trufflehog": {
                "VERSION": "1",
                "IGNORE_SEARCH_PATTERN": [
                    "test"
                ],
                "MESSAGE_INFO_SAST_RM": "If you have doubts, visit https://discuss.apps.bancolombia.com/t/lanzamiento-csa-analisis-de-seguridad-en-contenedores/6199",
                "THRESHOLD": {
                    "VULNERABILITY": {
                        "Critical": 1,
                        "High": 1,
                        "Medium": 1,
                        "Low": 1
                    },
                    "COMPLIANCE": {
                        "Critical": 1
                    }
                }
            }
        }

        self.devops_platform_gateway.get_variable.return_value = "example_pipeline"

        self.tool_gateway.run_tool.return_value = (
            ["finding1", "finding2"],
            "/path/to/results",
        )

        findings_list, input_core = self.secret_scan.process(dict_args, tool)

        # Assert the expected return values
        self.assertEqual(findings_list, ["finding1", "finding2"])
        self.assertEqual(input_core.totalized_exclusions, [])
        self.assertEqual(input_core.threshold_defined.vulnerability.critical, 10)
        self.assertEqual(input_core.path_file_results, "/path/to/results")
        self.assertEqual(input_core.custom_message_break_build, "message test")
        self.assertEqual(input_core.scope_pipeline, "example_pipeline")
        self.assertEqual(input_core.stage_pipeline, "Pipeline")

    def test_process_skip_tool(self):
        dict_args = {
            "remote_config_repo": "example_repo",
            "environment": "test",
            "platform": "eks",
        }
        tool = "TRUFFLEHOG"

        self.devops_platform_gateway.get_remote_config.side_effect = [
            # Resultado para el primer llamado (init_config_tool)
            {
                "trufflehog": {
                    "VERSION": "1",
                    "IGNORE_SEARCH_PATTERN": [
                        "test"
                    ],
                    "MESSAGE_INFO_SAST_RM": "If you have doubts, visit https://discuss.apps.bancolombia.com/t/lanzamiento-csa-analisis-de-seguridad-en-contenedores/6199",
                    "THRESHOLD": {
                        "VULNERABILITY": {
                            "Critical": 1,
                            "High": 1,
                            "Medium": 1,
                            "Low": 1
                        },
                        "COMPLIANCE": {
                            "Critical": 1
                        }
                    }
                }
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

        findings_list, input_core = self.iac_scan.process(dict_args, tool)

        # Assert the expected return values
        self.assertEqual(findings_list, [])
        self.assertIsNotNone(input_core)
