import unittest
from unittest.mock import patch, MagicMock
from devsecops_engine_tools.engine_sast.engine_code.src.applications.runner_engine_code import (
    init_engine_sast_code
)

class TestInitEngineSastCode(unittest.TestCase):

    @patch(
        'devsecops_engine_tools.engine_sast.engine_code.src.infrastructure.entry_points.entry_point_tool.CodeScan'
    )
    def test_init_engine_sast_code(self, mock_code_scan):
        # Arrange
        mock_devops_platform_gateway = MagicMock()
        mock_tool_gateway = MagicMock()
        mock_git_gateway = MagicMock()
        
        dict_args = {'remote_config_repo': 'test_repo'}
        tool = 'TOOL_NAME'
        
        mock_code_scan_instance = MagicMock()
        mock_code_scan.return_value = mock_code_scan_instance
        mock_code_scan_instance.process.return_value = (["finding1"], "path/file/results")
        
        # Act
        findings_list, input_core = init_engine_sast_code(
            mock_devops_platform_gateway, 
            mock_tool_gateway, 
            dict_args, 
            mock_git_gateway, 
            tool
        )
        
        # Assert
        mock_code_scan.assert_called_once_with(
            mock_tool_gateway,
            mock_devops_platform_gateway,
            mock_git_gateway
        )
        mock_code_scan_instance.process.assert_called_once_with(dict_args, tool)
        self.assertEqual(findings_list, ["finding1"])
        self.assertEqual(input_core, "path/file/results")
