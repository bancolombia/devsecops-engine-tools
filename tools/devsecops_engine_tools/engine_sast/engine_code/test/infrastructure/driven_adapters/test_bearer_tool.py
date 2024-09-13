import unittest
from unittest.mock import patch, Mock, call
import subprocess
from devsecops_engine_tools.engine_sast.engine_code.src.infrastructure.driven_adapters.bearer.bearer_tool import (
    BearerTool
)

class TestBearerTool(unittest.TestCase):

    @patch(
        "subprocess.run"
    )
    def test_install_tool_command_not_found(self, mock_subprocess):
        # Arrange
        mock_subprocess.return_value = Mock(stderr=b"bearer: command not found", decode=lambda: "bearer: command not found")
        tool = BearerTool()
        agent_work_folder = "/agent/work/folder"

        # Act
        tool.install_tool(agent_work_folder)
        
        # Assert
        install_command = f"curl -sfL https://raw.githubusercontent.com/Bearer/bearer/main/contrib/install.sh | sh -s -- -b {agent_work_folder}/bin"
        mock_subprocess.assert_has_calls([
            call(f"{agent_work_folder}/bin/bearer version", capture_output=True, shell=True),
            call(install_command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        ])

    @patch(
        "subprocess.run"
    )
    def test_install_tool_already_installed(self, mock_subprocess):
        # Arrange
        mock_subprocess.return_value = Mock(stderr=b"", decode=lambda: "")
        tool = BearerTool()
        agent_work_folder = "/agent/work/folder"

        # Act
        tool.install_tool(agent_work_folder)
        
        # Assert
        mock_subprocess.assert_called_once_with(f"{agent_work_folder}/bin/bearer version", capture_output=True, shell=True)

    def test_config_data(self):
        # Arrange
        tool = BearerTool()
        agent_work_folder = "/agent/work/folder"
        list_skip_rules = ["vul_id1", "vul_id2"]
        list_rules = ["rule1", "rule2"]

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
                "only-rule": list_rules
            }
        }

        # Act
        result = tool.config_data(agent_work_folder, list_skip_rules, list_rules)

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
        list_rules = ["rule1", "rule2"]

        # Act
        tool.create_config_file(agent_work_folder, list_skip_rules, list_rules)

        # Assert
        mock_open.assert_called_once_with(f"{agent_work_folder}/bearer.yml", "w")
        mock_yaml_dump.assert_called_once_with(
            tool.config_data(agent_work_folder, list_skip_rules, list_rules),
            mock_open(),
            default_flow_style=False
        )

    def test_skip_rules_list(self):
        # Arrange
        tool = BearerTool()
        list_exclusions = [Mock(where="file1", id="vul_id1"), Mock(where="all", id="vul_id2"), Mock(where="file2", id="vul_id3")]
        pull_file = "file1"
        
        # Act
        result = tool.skip_rules_list(list_exclusions, pull_file)

        # Assert
        self.assertEqual(result, ["vul_id1", "vul_id2"])
    
    @patch(
        "subprocess.run"
    )
    @patch(
        "devsecops_engine_tools.engine_sast.engine_code.src.infrastructure.driven_adapters.bearer.bearer_tool.BearerDeserealizator.get_list_finding"
    )
    @patch(
        "devsecops_engine_tools.engine_sast.engine_code.src.infrastructure.driven_adapters.bearer.bearer_tool.BearerTool.install_tool"
    )
    @patch(
        "devsecops_engine_tools.engine_sast.engine_code.src.infrastructure.driven_adapters.bearer.bearer_tool.BearerTool.create_config_file"
    )
    def test_run_tool_with_folder_to_scan(self, mock_create_config_file, mock_install_tool, mock_get_list_finding, mock_subprocess):
        # Arrange
        tool = BearerTool()
        pull_request_files, list_exclusions = [], []
        folder_to_scan = "/path/to/scan"
        agent_work_folder = "/agent/work/folder"
        repository = "test_repo"
        list_rules = ["rule1", "rule2"]
        mock_get_list_finding.return_value = ["finding1", "finding2"]

        # Act
        findings, path_file_results = tool.run_tool(
            folder_to_scan,
            pull_request_files,
            agent_work_folder,
            repository,
            list_exclusions,
            list_rules
        )

        # Assert
        mock_install_tool.assert_called_once_with(agent_work_folder)
        mock_create_config_file.assert_called_once_with(agent_work_folder)
        expected_command = f"{agent_work_folder}/bin/bearer scan {folder_to_scan} --config-file {agent_work_folder}/bearer.yml"
        mock_subprocess.assert_called_once_with(expected_command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        mock_get_list_finding.assert_called_once_with(f"{agent_work_folder}/bearer-scan.json", agent_work_folder)
        self.assertEqual(findings, ["finding1", "finding2"])
        self.assertEqual(path_file_results, f"{agent_work_folder}/bearer-scan.json")
    
    @patch(
        "subprocess.run"
    )
    @patch(
        "devsecops_engine_tools.engine_sast.engine_code.src.infrastructure.driven_adapters.bearer.bearer_tool.BearerDeserealizator.get_list_finding"
    )
    @patch(
        "devsecops_engine_tools.engine_sast.engine_code.src.infrastructure.driven_adapters.bearer.bearer_tool.BearerTool.install_tool"
    )
    @patch(
        "devsecops_engine_tools.engine_sast.engine_code.src.infrastructure.driven_adapters.bearer.bearer_tool.BearerTool.create_config_file"
    )
    @patch(
        "devsecops_engine_tools.engine_sast.engine_code.src.infrastructure.driven_adapters.bearer.bearer_tool.BearerScanFileMaker.add_vulnerabilities"
    )
    @patch(
        "devsecops_engine_tools.engine_sast.engine_code.src.infrastructure.driven_adapters.bearer.bearer_tool.BearerScanFileMaker.make_scan_file"
    )
    def test_run_tool_with_pull_request_files(self,mock_bearer_scan_file_maker_create, mock_bearer_scan_file_maker_add, mock_create_config_file, mock_install_tool, mock_get_list_finding, mock_subprocess):
        # Arrange
        tool = BearerTool()
        folder_to_scan = None
        pull_request_files = ["file1.js", "file2.js"]
        agent_work_folder = "/agent/work/folder"
        repository = "test_repo"
        list_exclusions = [Mock(where="file_test.js", id="vul_id1")]
        list_rules = ["rule1", "rule2"]
        mock_get_list_finding.side_effect = [["finding1"], ["finding2"]]

        # Act
        findings, _ = tool.run_tool(
            folder_to_scan,
            pull_request_files,
            agent_work_folder,
            repository,
            list_exclusions,
            list_rules
        )

        # Assert
        mock_install_tool.assert_called_once_with(agent_work_folder)
        mock_create_config_file.assert_has_calls([
                call(agent_work_folder, list_skip_rules=tool.skip_rules_list(list_exclusions, "file1.js"), list_rules=list_rules),
                call(agent_work_folder, list_skip_rules=tool.skip_rules_list(list_exclusions, "file2.js"), list_rules=list_rules)
            ]     
        )
        expected_command_file1 = f"{agent_work_folder}/bin/bearer scan {agent_work_folder}/{repository}/file1.js --config-file {agent_work_folder}/bearer.yml"
        expected_command_file2 = f"{agent_work_folder}/bin/bearer scan {agent_work_folder}/{repository}/file2.js --config-file {agent_work_folder}/bearer.yml"
        mock_subprocess.assert_has_calls([
                call(expected_command_file1, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True),
                call(expected_command_file2, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            ]     
        )
        mock_bearer_scan_file_maker_add.assert_has_calls([
                call(f"{agent_work_folder}/bearer-scan.json"),
                call(f"{agent_work_folder}/bearer-scan.json")
            ]     
        )
        mock_bearer_scan_file_maker_create.assert_called_once_with(agent_work_folder)
        mock_get_list_finding.assert_has_calls([
                call(f"{agent_work_folder}/bearer-scan.json", agent_work_folder),
                call(f"{agent_work_folder}/bearer-scan.json", agent_work_folder)
            ]     
        )
        self.assertEqual(findings, ["finding1", "finding2"])
