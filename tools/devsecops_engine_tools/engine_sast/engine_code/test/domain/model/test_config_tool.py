import unittest
from unittest.mock import patch
from devsecops_engine_tools.engine_sast.engine_code.src.domain.model.config_tool import (
    ConfigTool
)

@patch(
    "devsecops_engine_tools.engine_sast.engine_code.src.domain.model.config_tool.Threshold"
)
class TestConfigTool(unittest.TestCase):
    
    def test_config_tool_initialization(self, mock_threshold):
        # JSON Simulated data (Arrange)
        mock_json_data = {
            "IGNORE_SEARCH_PATTERN": [
            "test"
            ],
            "MESSAGE_INFO_ENGINE_CODE": "test message",
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
            },
            "TOOL_NAME": {
                "EXCLUDE_FOLDER": ["test"]
            },
            "TARGET_BRANCHES": ["trunk", "develop"]
        }
        
        tool = "TOOL_NAME"
        scope = "pipeline"

        # Act
        config_tool = ConfigTool(mock_json_data, tool, scope)

        # Assert
        self.assertEqual(config_tool.ignore_search_pattern, ["test"])
        self.assertEqual(config_tool.message_info_engine_code, "test message")
        mock_threshold.assert_called_once_with(mock_json_data["THRESHOLD"])
        self.assertEqual(config_tool.target_branches, ["trunk", "develop"])
        self.assertEqual(config_tool.exclude_folder, ["test"])
        self.assertEqual(config_tool.scope_pipeline, "pipeline")
