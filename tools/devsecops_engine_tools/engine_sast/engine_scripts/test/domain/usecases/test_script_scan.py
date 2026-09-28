import unittest
from unittest.mock import MagicMock
from devsecops_engine_tools.engine_sast.engine_scripts.src.domain.usecases.script_scan import (
    ScriptScan,
)


class TestScriptScan(unittest.TestCase):
    def setUp(self):
        self.tool_gateway = MagicMock()
        self.devops_platform_gateway = MagicMock()
        self.remote_config_source_gateway = MagicMock()
        self.script_scan = ScriptScan(
            self.tool_gateway, self.devops_platform_gateway, self.remote_config_source_gateway
        )

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
            "platform": "all",
            "token_external_checks": "token",
            "context": "false",
        }
        secret_tool = "example_secret"
        tool = "SCRIPT"

        self.remote_config_source_gateway.get_remote_config.return_value = {
            "SEARCH_PATTERN": ["AW", "NU"],
            "IGNORE_SEARCH_PATTERN": "(.*_test)",
            "MESSAGE_INFO_ENGINE_SCRIPTS": "message test",
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
            "SCRIPT": {
                "TIMEOUT_SECONDS": 120,
                "DEFAULT_SEVERITY": "high",
                "DEFAULT_CATEGORY": "vulnerability",
                "RULES": "",
            },
        }

        self.devops_platform_gateway.get_variable.side_effect = self.side_effect

        self.tool_gateway.run_tool.return_value = (
            ["finding1", "finding2"],
            "/path/to/results",
        )

        findings_list, input_core = self.script_scan.process(dict_args, secret_tool, tool, "pdn")

        self.assertEqual(findings_list, ["finding1", "finding2"])
        self.assertEqual(input_core.totalized_exclusions, [])
        self.assertEqual(input_core.threshold_defined.vulnerability.critical, 10)
        self.assertEqual(input_core.path_file_results, "/path/to/results")
        self.assertEqual(input_core.custom_message_break_build, "message test")
        self.assertEqual(input_core.stage_pipeline, "Release")

    def test_process_skip_tool_by_ignore_search_pattern(self):
        dict_args = {
            "remote_config_repo": "example_repo",
            "remote_config_branch": "",
            "folder_path": "example_folder",
            "environment": "test",
            "platform": "all",
            "token_external_checks": "token",
            "context": "false",
        }
        secret_tool = "example_secret"
        tool = "SCRIPT"

        config_payload = {
            "SEARCH_PATTERN": ["AW", "NU"],
            "IGNORE_SEARCH_PATTERN": "(.*example_pipeline)",
            "MESSAGE_INFO_ENGINE_SCRIPTS": "message test",
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
            "SCRIPT": {
                "TIMEOUT_SECONDS": 120,
                "DEFAULT_SEVERITY": "high",
                "DEFAULT_CATEGORY": "vulnerability",
                "RULES": "",
            },
        }
        self.remote_config_source_gateway.get_remote_config.side_effect = [
            config_payload,
            {},
        ]
        self.devops_platform_gateway.get_variable.side_effect = self.side_effect

        findings_list, input_core = self.script_scan.process(dict_args, secret_tool, tool, "pdn")

        self.tool_gateway.run_tool.assert_not_called()
        self.assertEqual(findings_list, [])
        self.assertIsNone(input_core.path_file_results)
        self.assertEqual(dict_args["send_metrics"], "false")
        self.assertEqual(dict_args["use_vulnerability_management"], "false")


if __name__ == "__main__":
    unittest.main()
