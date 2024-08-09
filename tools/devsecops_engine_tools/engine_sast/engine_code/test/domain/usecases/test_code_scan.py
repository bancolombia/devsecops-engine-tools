import unittest
from unittest.mock import Mock, patch
from devsecops_engine_tools.engine_sast.engine_code.src.domain.model.gateways.tool_gateway import (
    ToolGateway
)
from devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway import (
    DevopsPlatformGateway
)
from devsecops_engine_tools.engine_sast.engine_code.src.domain.model.gateways.git_gateway import (
    GitGateway
)
from devsecops_engine_tools.engine_sast.engine_code.src.domain.usecases.code_scan import (
    CodeScan
)

class TestCodeScan(unittest.TestCase):

    def setUp(self):
        self.mock_json_data = None

        # Mock gateways
        self.mock_tool_gateway = Mock(spec=ToolGateway)
        self.mock_devops_platform_gateway = Mock(spec=DevopsPlatformGateway)
        self.mock_git_gateway = Mock(spec=GitGateway)

        # CodeScan instance with Mocks
        self.code_scan = CodeScan(
            tool_gateway=self.mock_tool_gateway,
            devops_platform_gateway=self.mock_devops_platform_gateway,
            git_gateway=self.mock_git_gateway
        )

    @patch(
            "devsecops_engine_tools.engine_sast.engine_code.src.domain.usecases.code_scan.ConfigTool"
    )
    def test_set_config_tool(self, mock_config_tool):
        # Arrange
        self.mock_devops_platform_gateway.get_remote_config.return_value = {"test_key": "test_value"}
        self.mock_devops_platform_gateway.get_variable.return_value = "pipeline_test_name"

        # Act
        self.code_scan.set_config_tool({"remote_config_repo": "test_repo"}, "TOOL_NAME")

        # Assert
        self.mock_devops_platform_gateway.get_remote_config.assert_called_once_with(
            "test_repo", "engine_sast/engine_code/ConfigTool.json"
        )
        self.mock_devops_platform_gateway.get_variable.assert_called_once_with("pipeline_name")
        mock_config_tool.assert_called_once_with(
            json_data={"test_key": "test_value"},
            tool="TOOL_NAME",
            scope="pipeline_test_name"
        )
    
    def test_get_pull_request_files(self):
        # Arrange
        self.mock_devops_platform_gateway.get_variable.side_effect = [
            "work_folder_value", "target_branch_value", "source_branch_value", "access_token_value", 
            "organization_value", "project_name_value", "repository_value", "repository_provider_value"
        ]
        self.mock_git_gateway.get_files_pull_request.return_value = ["file1", "file2"]

        # Act
        files = self.code_scan.get_pull_request_files(["trunk", "develop"])

        # Assert
        self.mock_devops_platform_gateway.get_variable.assert_any_call("work_folder")
        self.mock_git_gateway.get_files_pull_request.assert_called_once_with(
            "work_folder_value", "target_branch_value", ["trunk", "develop"], "source_branch_value",
            "access_token_value", "organization_value", "project_name_value", "repository_value",
            "repository_provider_value"
        )
        self.assertEqual(files, ["file1", "file2"])
    
    @patch(
        "devsecops_engine_tools.engine_sast.engine_code.src.domain.usecases.code_scan.Exclusions"
    )
    def test_get_exclusions_all_pipelines(self, mock_exclusions):
        # Arrange
        self.mock_devops_platform_gateway.get_remote_config.return_value = {
            "All":{
                "TOOL_NAME": [
                    {
                        "id": "vul id",
                        "create_date": "18102023",
                        "expired_date": "18042024",
                        "hu": "4338704",
                        "severity": "low",
                    }
                ],
            }
        }
        self.mock_devops_platform_gateway.get_variable.return_value = "pipeline_test_name"
        mock_exclusions.return_value = Mock()

        # Act
        exclusions, skip_tool = self.code_scan.get_exclusions({"remote_config_repo": "test_repo"}, "TOOL_NAME")

        # Aserciones
        self.mock_devops_platform_gateway.get_remote_config.assert_called_once_with(
            "test_repo", "engine_sast/engine_code/Exclusions.json"
        )
        self.assertFalse(skip_tool)
        mock_exclusions.assert_called_with(
            id="vul id", where="", create_date="18102023", expired_date="18042024", severity="low", hu="4338704", reason="Risk acceptance"
        )
        self.assertEqual(len(exclusions), 1)
    
    @patch(
        "devsecops_engine_tools.engine_sast.engine_code.src.domain.usecases.code_scan.Exclusions"
    )
    def test_get_exclusions_specific_pipeline(self, mock_exclusions):
        # Arrange
        self.mock_devops_platform_gateway.get_remote_config.return_value = {
            "pipeline_test_name":{
                "TOOL_NAME": [
                    {
                        "id": "vul id",
                        "create_date": "18102023",
                        "expired_date": "18042024",
                        "hu": "4338704",
                        "severity": "low",
                    }
                ],
            }
        }
        self.mock_devops_platform_gateway.get_variable.return_value = "pipeline_test_name"
        mock_exclusions.return_value = Mock()

        # Act
        exclusions, skip_tool = self.code_scan.get_exclusions({"remote_config_repo": "test_repo"}, "TOOL_NAME")

        # Assert
        self.mock_devops_platform_gateway.get_remote_config.assert_called_once_with(
            "test_repo", "engine_sast/engine_code/Exclusions.json"
        )
        self.assertFalse(skip_tool)
        mock_exclusions.assert_called_with(
            id="vul id", where="", create_date="18102023", expired_date="18042024", severity="low", hu="4338704", reason="Risk acceptance"
        )
        self.assertEqual(len(exclusions), 1)
    
    @patch(
        "devsecops_engine_tools.engine_sast.engine_code.src.domain.usecases.code_scan.Exclusions"
    )
    def test_get_exclusions_skip_tool(self, mock_exclusions):
        # Arrange
        self.mock_devops_platform_gateway.get_remote_config.return_value = {
            "pipeline_test_name":{
                "SKIP_TOOL": {
                    "create_date": "24012024",
                    "expired_date": "30012024",
                    "hu": "3423213"
                }
            }
        }
        self.mock_devops_platform_gateway.get_variable.return_value = "pipeline_test_name"
        mock_exclusions.return_value = Mock()

        # Act
        exclusions, skip_tool = self.code_scan.get_exclusions({"remote_config_repo": "test_repo"}, "TOOL_NAME")

        # Assert
        self.mock_devops_platform_gateway.get_remote_config.assert_called_once_with(
            "test_repo", "engine_sast/engine_code/Exclusions.json"
        )
        self.assertTrue(skip_tool)
        self.assertEqual(exclusions, [])
    
    def test_apply_exclude_folder(self):
        # Arrange
        exclude_folder_true = ["test_folder"]
        exclude_folder_false = ["folder"]
        path = "home/user/test_folder/test.txt"

        #Act
        result_true = self.code_scan.apply_exclude_folder(exclude_folder_true, path)
        result_false = self.code_scan.apply_exclude_folder(exclude_folder_false, path)

        #Assert
        self.assertTrue(result_true)
        self.assertFalse(result_false)

    @patch(
        "devsecops_engine_tools.engine_sast.engine_code.src.domain.usecases.code_scan.InputCore"
    )
    def test_process(self, mock_input_core):
        # Arrange
        self.code_scan.set_config_tool = Mock(return_value=Mock(scope_pipeline="test_scope"))
        self.code_scan.get_exclusions = Mock(return_value=(["exclusion1"], False))
        self.code_scan.get_pull_request_files = Mock(return_value=["file1.js", "file2.js"])
        self.code_scan.apply_exclude_folder = Mock(return_value=False)
        self.mock_tool_gateway.run_tool.return_value = (["finding1", "finding2"], "path/to/results")
        self.mock_devops_platform_gateway.get_variable.side_effect = ["test_work_folder", "test_repo", "test_stage"]

        # Act
        findings_list, _ = self.code_scan.process({"folder_path": None, "remote_config_repo": "some_repo"}, "TOOL_NAME")

        # Assert
        self.code_scan.set_config_tool.assert_called_once()
        self.code_scan.get_exclusions.assert_called_once()
        self.code_scan.get_pull_request_files.assert_called_once()
        self.mock_tool_gateway.run_tool.assert_called_once_with(
            None, ["file1.js", "file2.js"], "test_work_folder", "test_repo", ["exclusion1"]
        )
        mock_input_core.assert_called_once_with(
            totalized_exclusions=["exclusion1"], threshold_defined=self.code_scan.set_config_tool.return_value.threshold,
            path_file_results="path/to/results", custom_message_break_build=self.code_scan.set_config_tool.return_value.message_info_engine_code,
            scope_pipeline="test_scope", stage_pipeline="Test_stage"
        )
        self.assertEqual(findings_list, ["finding1", "finding2"])

    @patch(
        "devsecops_engine_tools.engine_sast.engine_code.src.domain.usecases.code_scan.InputCore"
    )
    def test_process_skip_tool(self, mock_input_core):
        # Arrange
        self.code_scan.set_config_tool = Mock(return_value=Mock(scope_pipeline="test_scope"))
        self.code_scan.get_exclusions = Mock(return_value=(["exclusion1"], True))
        self.mock_devops_platform_gateway.get_variable.return_value = "test_stage"

        # Act
        findings_list, _ = self.code_scan.process({"folder_path": None, "remote_config_repo": "some_repo"}, "TOOL_NAME")

        # Assert
        self.code_scan.set_config_tool.assert_called_once()
        self.code_scan.get_exclusions.assert_called_once()
        self.mock_tool_gateway.run_tool.assert_not_called()
        self.assertEqual(findings_list, [])
        mock_input_core.assert_called_once_with(
            totalized_exclusions=["exclusion1"], threshold_defined=self.code_scan.set_config_tool.return_value.threshold,
            path_file_results="", custom_message_break_build=self.code_scan.set_config_tool.return_value.message_info_engine_code,
            scope_pipeline="test_scope", stage_pipeline="Test_stage"
        )
