import unittest
from unittest.mock import patch, Mock, call, MagicMock, mock_open, ANY
import subprocess
import os
from devsecops_engine_tools.engine_sast.engine_code.src.infrastructure.driven_adapters.bearer.bearer_tool import (
    BearerTool
)

class TestBearerTool(unittest.TestCase):

    @patch(
        "subprocess.run"
    )
    def test_install_tool_command_not_found(self, mock_subprocess):
        # Arrange
        mock_subprocess.side_effect = [
            MagicMock(returncode=1),  # "bearer version" fails
            MagicMock(returncode=1),  # first try of instalation fails
            MagicMock(returncode=0),  # second try success
         ]
        tool = BearerTool()

        # Act
        tool.install_tool()
        
        # Assert
        install_command = f"curl -sfL https://raw.githubusercontent.com/Bearer/bearer/main/contrib/install.sh | sh -s -- -b /usr/local/bin"
        mock_subprocess.assert_has_calls([
            call(f"bearer version", capture_output=True, shell=True),
            call(install_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True),
            call(install_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True),
        ])

    @patch(
        "subprocess.run"
    )
    def test_install_tool_already_installed(self, mock_subprocess):
        # Arrange
        mock_subprocess.return_value = Mock(returncode=0)
        tool = BearerTool()

        # Act
        tool.install_tool()
        
        # Assert
        mock_subprocess.assert_called_once_with("bearer version", capture_output=True, shell=True)

    def test_config_data(self):
        # Arrange
        tool = BearerTool()
        agent_work_folder = "/agent/work/folder"
        list_skip_rules = ["vul_id1", "vul_id2"]

        expected_data = {
            "report": {
                "output": f"{agent_work_folder}/bearer-scan.json",
                "format": "json",
                "report": "security",
                "severity": "critical,high,medium,low"
            },
            "scan": {
                "disable-domain-resolution": True,
                "domain-resolution-timeout": "3s",
                "exit-code": 0,
                "scanner": ["sast"]
            },
            "rule": {
                "skip-rule": list_skip_rules,
            }
        }

        # Act
        result = tool.config_data(agent_work_folder, list_skip_rules)

        # Assert
        self.assertEqual(result, expected_data)

    @patch(
        "yaml.dump"
    )
    @patch(
        "builtins.open", new_callable=unittest.mock.mock_open
    )
    def test_create_config_file(self, mock_open, mock_yaml_dump):
        # Arrange
        tool = BearerTool()
        agent_work_folder = "/agent/work/folder"
        list_skip_rules = ["vul_id1", "vul_id2"]

        # Act
        tool.create_config_file(agent_work_folder, list_skip_rules)

        # Assert
        mock_open.assert_called_once_with(f"{agent_work_folder}/bearer.yml", "w")
        mock_yaml_dump.assert_called_once_with(
            tool.config_data(agent_work_folder, list_skip_rules),
            mock_open(),
            default_flow_style=False
        )

    @patch(
        "os.makedirs"
    )
    @patch(
        "shutil.copy2"
    )
    def test_copy_file(self, mock_copy2, mock_makedirs):
        # Arrange
        pull_file = "file1.txt"
        agent_work_folder = "/agent/work/folder"
        repository = "my_repo"
        path_to_scan = "/agent/work/folder/copy_folder"
        tool = BearerTool()

        # Act
        tool.copy_file(pull_file, agent_work_folder, repository, path_to_scan)

        expected_destination_dir = os.path.join(path_to_scan, f"{repository}")
        mock_makedirs.assert_called_once_with(expected_destination_dir, exist_ok=True)

        expected_source_path = f"{agent_work_folder}/{repository}/{pull_file}"
        expected_destination_path = os.path.join(path_to_scan, f"{repository}/{pull_file}")

        # Assert
        mock_copy2.assert_called_once_with(expected_source_path, expected_destination_path)

    @patch(
        "subprocess.run"
    )
    @patch(
        "devsecops_engine_tools.engine_sast.engine_code.src.infrastructure.driven_adapters.bearer.bearer_tool.BearerDeserealizator.get_list_finding"
    )
    def test_scan_path(self, mock_get_list_finding, mock_run):
        # Arrange
        mock_run.return_value = MagicMock(returncode=0)
        mock_get_list_finding.return_value = ["finding1", "finding2"]
        path = "/path/to/scan/file.js"
        agent_work_folder = "/agent/work/folder"
        tool = BearerTool()

        # Act
        findings = tool.scan_path(path, agent_work_folder)

        # Assert
        mock_run.assert_called_once_with(
            f"bearer scan {path} --config-file {agent_work_folder}/bearer.yml",
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=True
        )
        mock_get_list_finding.assert_called_once_with(f"{agent_work_folder}/bearer-scan.json", agent_work_folder)
        self.assertEqual(findings, ["finding1", "finding2"])
    
    @patch(
        "builtins.open",
        new_callable=mock_open
    )
    @patch(
        "json.load"
    )
    @patch(
        "json.dump"
    )
    def test_format_scan_file(self, mock_json_dump, mock_json_load, mock_file_open):
        # Arrange
        mock_json_load.return_value = {
            "high": [{"name": "vul1"}]
        }
        scan_result_path = "/path/to/scan_result.json"
        agent_work_folder = "/agent/work/folder"
        tool = BearerTool()
        mock_file_open.side_effect = [
            mock_open(read_data='{"high": [{"name": "vul1"}]}').return_value,
            mock_open().return_value
        ]

        #Act
        result_path = tool.format_scan_file(scan_result_path, agent_work_folder)

        # Assert
        expected_path = f"{agent_work_folder}/bearer-scan-vul-man.json"
        mock_file_open.assert_any_call(scan_result_path, encoding="utf-8")
        mock_file_open.assert_any_call(expected_path, "w")
        mock_json_load.assert_called_once()
        expected_data = {"high": [{"name": "vul1", "snippet": ""}]}
        mock_json_dump.assert_called_once_with(expected_data, ANY)
        self.assertEqual(result_path, expected_path)

    @patch.object(
        BearerTool, 
        "install_tool"
    )
    @patch.object(
        BearerTool, 
        "create_config_file"
    )
    @patch.object(
        BearerTool, 
        "scan_path"
    )
    @patch.object(
        BearerTool, 
        "format_scan_file"
    )
    def test_run_tool_with_folder_to_scan(self, mock_format_scan_file, mock_scan_path, mock_create_config_file, mock_install_tool):
        # Arrange
        tool = BearerTool()
        mock_scan_path.return_value = "findings_data"
        mock_format_scan_file.return_value = "formatted_scan"
        folder_to_scan = "/test/folder"
        pull_request_files = ["file1.txt", "file2.txt"]
        agent_work_folder = "/agent/work/folder"
        repository = "repo"
        config_tool = MagicMock()
        config_tool.data = {
            tool.BEARER_TOOL: {
                "EXCLUDED_RULES": ["rule1", "rule2"],
                "NUMBER_THREADS": 4
            }
        }
        
        # Act
        findings, scan_result_path_formatted = tool.run_tool(
            folder_to_scan, pull_request_files, agent_work_folder, repository, config_tool
        )
        
        # Assert
        mock_install_tool.assert_called_once()
        mock_create_config_file.assert_called_once_with(agent_work_folder, ["rule1", "rule2"])
        mock_scan_path.assert_called_once_with(folder_to_scan, agent_work_folder)
        mock_format_scan_file.assert_called_once_with(f"/agent/work/folder/bearer-scan.json", agent_work_folder)
        
        self.assertEqual(findings, "findings_data")
        self.assertEqual(scan_result_path_formatted, "formatted_scan")
    
    @patch(
        "os.makedirs"
    )
    @patch(
        "concurrent.futures.ThreadPoolExecutor"
    )
    @patch.object(
        BearerTool, 
        "install_tool"
    )
    @patch.object(
        BearerTool, 
        "create_config_file"
    )
    @patch.object(
        BearerTool, 
        "copy_file"
    )
    @patch.object(
        BearerTool, 
        "scan_path"
    )
    @patch.object(
        BearerTool, 
        "format_scan_file"
    )
    def test_run_tool_without_folder(self, mock_format_scan_file, mock_scan_path, mock_copy_file, mock_create_config_file, 
                                     mock_install_tool, mock_thread_pool, mock_makedirs):
        # Arrange
        tool = BearerTool()
        mock_scan_path.return_value = "findings_data"
        mock_format_scan_file.return_value = "formatted_scan"
        mock_executor = MagicMock()
        mock_future = MagicMock()
        mock_executor.submit.return_value = mock_future
        mock_future.result.return_value = None
        mock_thread_pool.return_value.__enter__.return_value = mock_executor
        folder_to_scan = None
        pull_request_files = ["file1.txt", "file2.txt"]
        agent_work_folder = "/agent/work/folder"
        repository = "repo"
        config_tool = MagicMock()
        config_tool.data = {
            tool.BEARER_TOOL: {
                "EXCLUDED_RULES": ["rule1", "rule2"],
                "NUMBER_THREADS": 4
            }
        }
        
        # Act
        findings, scan_result_path_formatted = tool.run_tool(
            folder_to_scan, pull_request_files, agent_work_folder, repository, config_tool
        )
        
        # Assert
        folder_copy_files = f"{agent_work_folder}/copy_files_bearer"
        mock_install_tool.assert_called_once()
        mock_create_config_file.assert_called_once_with(agent_work_folder, ["rule1", "rule2"])
        mock_makedirs.assert_called_once_with(folder_copy_files, exist_ok=True)
        mock_executor.submit.assert_any_call(tool.copy_file, "file1.txt", agent_work_folder, repository, folder_copy_files)
        mock_executor.submit.assert_any_call(tool.copy_file, "file2.txt", agent_work_folder, repository, folder_copy_files)
        mock_scan_path.assert_called_once_with(folder_copy_files, agent_work_folder)
        mock_format_scan_file.assert_called_once_with(f"/agent/work/folder/bearer-scan.json", agent_work_folder)

        self.assertEqual(findings, "findings_data")
        self.assertEqual(scan_result_path_formatted, "formatted_scan")