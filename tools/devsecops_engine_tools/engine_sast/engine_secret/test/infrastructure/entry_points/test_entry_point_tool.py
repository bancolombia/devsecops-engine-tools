import unittest
from unittest.mock import Mock, patch
from devsecops_engine_tools.engine_sast.engine_secret.src.domain.model.DeserializeConfigTool import DeserializeConfigTool
from devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.entry_points.entry_point_tool import engine_secret_scan

class TestEngineSecretScan(unittest.TestCase):

    @patch('devsecops_engine_tools.engine_sast.engine_secret.src.domain.usecases.secret_scan.SecretScan')
    @patch('devsecops_engine_tools.engine_sast.engine_secret.src.domain.usecases.set_input_core.SetInputCore')
    def test_engine_secret_scan(self, MockSetInputCore, MockSecretScan):
        mock_devops_platform_gateway = Mock()
        mock_tool_gateway = Mock()
        mock_dict_args = {
            "remote_config_repo": "fake_repo"
        }
        mock_tool = "TRUFFLEHOG"
        mock_tool_deserealizator = Mock()
        mock_git_gateway = Mock()
        json_exclusion = {
            "pipeline_name_carlos":{
                "SKIP_TOOL": {
                    "create_date": "24012023",
                    "expired_date": "21092024",
                    "hu": ""
                }
            }
        }
        json_config = {
            "IGNORE_SEARCH_PATTERN": [
                "test"
            ],
            "MESSAGE_INFO_ENGINE_SECRET": "If you have doubts, visit url",
            "THRESHOLD": {
                "VULNERABILITY": {
                    "Critical": 1,
                    "High": 1,
                    "Medium": 1,
                    "Low": 1
                },
                "COMPLIANCE": {
                    "Critical": 0
                }
            },
            "TARGET_BRANCHES": ["trunk", "develop"],
            "trufflehog": {
                "EXCLUDE_PATH": [".git"],
                "NUMBER_THREADS": 4
            }
        }
        obj_config_tool = DeserializeConfigTool(json_config, 'trufflehog')
        mock_devops_platform_gateway.get_remote_config.side_effect = [json_exclusion ,json_config, json_exclusion]
        
        mock_secret_scan_instance = MockSecretScan.return_value
        mock_secret_scan_instance.complete_config_tool.return_value = obj_config_tool
        mock_devops_platform_gateway.get_variable.side_effect = ["pipeline_name_carlos","pipeline_name_carlos", "pipeline_name", "build"]
        mock_secret_scan_instance.process.return_value = ([], "")
        
        mock_set_input_core_instance = MockSetInputCore.return_value
        mock_set_input_core_instance.set_input_core.return_value = "input_core_result"

        findings, input_core_result = engine_secret_scan(
            mock_devops_platform_gateway,
            mock_tool_gateway,
            mock_dict_args,
            mock_tool,
            mock_tool_deserealizator,
            mock_git_gateway
        )
        
        self.assertEqual(findings, [])
