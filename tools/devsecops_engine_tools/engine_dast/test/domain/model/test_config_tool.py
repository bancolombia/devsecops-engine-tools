import unittest
from unittest.mock import MagicMock, patch
from devsecops_engine_tools.engine_dast.src.domain.model.config_tool import (
    ConfigTool)
from devsecops_engine_tools.engine_core.src.domain.model.threshold import Threshold


class TestConfigTool(unittest.TestCase):

    def setUp(self):
        self.mock_json_data = {
            "NUCLEI": {
                "VERSION": "1.0",
                "EXCLUSIONS_PATH": "/path/to/exclusions",
                "USE_EXTERNAL_CHECKS_DIR": "True",
                "EXTERNAL_DIR_OWNER": "owner",
                "EXTERNAL_DIR_REPOSITORY": "repository",
                "EXTERNAL_DIR_ASSET_NAME": "asset_name",
                "EXTERNAL_CHECKS_PATH": "/path/to/external/checks",
                "RULES": "rules_data_type"
            },
            "THRESHOLD": {
                "VULNERABILITY": {
                    "Critical": 1,
                    "High": 5,
                    "Medium": 10,
                    "Low": 20
                    },
                "COMPLIANCE": {
                    "Critical": 1
                }
                },
            "MESSAGE_INFO_DAST": "info"
        }
        self.tool = "NUCLEI"
        self.config_tool = ConfigTool(self.mock_json_data, self.tool)

    def test_initialization(self):
        self.assertEqual(self.config_tool.version, "1.0")
        self.assertEqual(self.config_tool.exclusions_path, "/path/to/exclusions")
        self.assertTrue(self.config_tool.use_external_checks_git)
        self.assertEqual(self.config_tool.external_checks_git, "git@example.com:repo.git")
        self.assertEqual(self.config_tool.use_external_checks_dir, "True")
        self.assertEqual(self.config_tool.external_dir_owner, "owner")
        self.assertEqual(self.config_tool.external_dir_repository, "repository")
        self.assertEqual(self.config_tool.external_asset_name, "asset_name")
        self.assertEqual(self.config_tool.external_checks_save_path, "/path/to/external/checks")
        self.assertEqual(self.config_tool.message_info_dast, "info")
        self.assertIsInstance(self.config_tool.threshold, Threshold)
        self.assertEqual(self.config_tool.threshold.vulnerability.critical, 1)
        self.assertEqual(self.config_tool.threshold.vulnerability.high, 5)
        self.assertEqual(self.config_tool.threshold.vulnerability.medium, 10)
        self.assertEqual(self.config_tool.threshold.vulnerability.low, 20)
        self.assertEqual(self.config_tool.rules_data_type, "rules_data_type")
        self.assertEqual(self.config_tool.scope_pipeline, "")
        self.assertIsNone(self.config_tool.exclusions)
        self.assertIsNone(self.config_tool.exclusions_all)
        self.assertIsNone(self.config_tool.exclusions_scope)
        self.assertEqual(self.config_tool.rules_all, {})