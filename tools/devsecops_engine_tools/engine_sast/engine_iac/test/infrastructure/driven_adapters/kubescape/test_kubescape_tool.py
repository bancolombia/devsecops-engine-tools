import json
import unittest
import subprocess
import logging
import shlex
from unittest.mock import MagicMock, patch, mock_open, call
from unittest import mock
from devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kubescape.kubescape_tool import (
    KubescapeTool
)
from devsecops_engine_tools.engine_sast.engine_iac.src.domain.model.config_tool import (
    ConfigTool,
)

logger = logging.getLogger()
logger.setLevel(logging.ERROR)
stream_handler = logging.StreamHandler()
logger.addHandler(stream_handler)


class TestKubescapeTool(unittest.TestCase):

    def setUp(self):
        self.kubescape_tool = KubescapeTool()

    @patch("builtins.open", new_callable=mock_open)
    @patch('devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kubescape.kubescape_tool.requests.get')
    def test_download_tool_success(self, mock_get, mock_file):

        mock_response = MagicMock()
        mock_response.content = b'Test content'
        mock_get.return_value = mock_response

        url = "http://example.com/test"
        file = "testfile.bin"

        self.kubescape_tool._download_tool(file, url)
        
        mock_get.assert_called_once_with(url, allow_redirects=True)

        mock_file().write.assert_called_once_with(b'Test content')

    @patch("devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kubescape.kubescape_tool.subprocess.run")
    @patch("devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kubescape.kubescape_tool.logger")
    @patch.object(KubescapeTool, "_download_tool")
    def test_install_tool_aleady_installed(self, mock_download_tool, mock_logger, mock_subprocess_run):
        mock_installed = MagicMock()
        mock_installed.returncode = 0
        mock_subprocess_run.return_value = mock_installed

        file = "testfile"
        url = "http://example.com/test"
        tool = self.kubescape_tool
        tool._install_tool(file, url)

        mock_subprocess_run.assert_called_once_with(
            ["which", f"./{shlex.quote(file)}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
        )

        mock_download_tool.assert_not_called()

        mock_logger.error.assert_not_called()

    @patch("devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kubescape.kubescape_tool.subprocess.run")
    @patch("devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kubescape.kubescape_tool.logger")
    @patch.object(KubescapeTool, "_download_tool")
    def test_install_tool_not_installed(self, mock_download_tool, mock_logger, mock_subprocess_run):
        mock_installed = MagicMock()
        mock_installed.returncode = 1
        mock_subprocess_run.side_effect = [mock_installed, MagicMock()]

        file = "testfile"
        url = "http://example.com/test"
        tool = self.kubescape_tool
        tool._install_tool(file, url)

        self.assertEqual(mock_subprocess_run.call_count, 2)
        mock_subprocess_run.assert_any_call(
            ["which", f"./{shlex.quote(file)}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
        )

        mock_subprocess_run.assert_any_call(["chmod", "+x", f"./{shlex.quote(file)}"], shell=False)

        mock_download_tool.assert_called_once_with(file, url)

        mock_logger.error.assert_not_called()

    @patch("devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kubescape.kubescape_tool.subprocess.run")
    @patch("devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kubescape.kubescape_tool.logger")
    @patch.object(KubescapeTool, "_download_tool")
    def test_install_tool_exception(self, mock_download_tool, mock_logger, mock_subprocess_run):
        mock_installed = MagicMock()
        mock_installed.returncode = 1
        mock_subprocess_run.side_effect = [mock_installed, MagicMock()]

        mock_download_tool.side_effect = Exception("Test exception")

        file = "testfile"
        url = "http://example.com/test"
        tool = self.kubescape_tool
        tool._install_tool(file, url)

        mock_subprocess_run.assert_called_once_with(
            ["which", f"./{shlex.quote(file)}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
        )

        mock_download_tool.assert_called_once_with(file, url)

        mock_logger.error.assert_called_once_with("Error installing Kubescape: Test exception")

    @patch("devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kubescape.kubescape_tool.subprocess.run")
    @patch("devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kubescape.kubescape_tool.logger")
    @patch.object(KubescapeTool, "_download_tool")
    def test_install_tool_windows_already_installed(self, mock_download_tool, mock_logger, mock_subprocess_run):
        mock_installed = MagicMock()
        mock_subprocess_run.return_value = mock_installed

        file = "testfile"
        url = "http://example.com/test"
        tool = self.kubescape_tool
        tool._install_tool_windows(file, url)

        mock_subprocess_run.assert_called_once_with(
            [f".\\{shlex.quote(file)}", "version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False
        )

        mock_download_tool.assert_not_called()

        mock_logger.error.assert_not_called()

    @patch("devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kubescape.kubescape_tool.subprocess.run", side_effect=FileNotFoundError)
    @patch("devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kubescape.kubescape_tool.logger")
    @patch.object(KubescapeTool, "_download_tool")
    def test_install_tool_windows_not_installed(self, mock_download_tool, mock_logger, mock_subprocess_run):
        mock_download_tool.return_value = None

        file = "testfile"
        url = "http://example.com/test"
        tool = self.kubescape_tool
        tool._install_tool_windows(file, url)

        mock_subprocess_run.assert_called_once_with(
            [f".\\{shlex.quote(file)}", "version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
        )

        mock_download_tool.assert_called_once_with(file, url)

        mock_logger.error.assert_not_called()

    @patch("devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kubescape.kubescape_tool.subprocess.run", side_effect=FileNotFoundError)
    @patch("devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kubescape.kubescape_tool.logger")
    @patch.object(KubescapeTool, "_download_tool", side_effect=Exception("Download exception"))
    def test_install_tool_windows_download_exception(self, mock_download_tool, mock_logger, mock_subprocess_run):

        file = "testfile"
        url = "http://example.com/test"
        tool = self.kubescape_tool
        tool._install_tool_windows(file, url)

        mock_subprocess_run.assert_called_once_with(
            [f".\\{shlex.quote(file)}", "version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
        )

        mock_download_tool.assert_called_once_with(file, url)

        mock_logger.error.assert_called_once_with("Error installing Kubescape: Download exception")

    @patch("devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kubescape.kubescape_tool.subprocess.run")
    @patch("devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kubescape.kubescape_tool.logger")
    def test_execute_kubescape_success(self, mock_logger, mock_subprocess_run):
        folders_to_scan = ["/path/to/folder1", "/path/to/folder2"]
        prefix = "kubescape"
        tool = self.kubescape_tool
        tool._execute_kubescape(folders_to_scan, prefix)

        expected_command = [
            "kubescape",
            "scan",
            shlex.quote("/path/to/folder1"),
            shlex.quote("/path/to/folder2"),
            "--format",
            "json",
            "--format-version",
            "v2",
            "--output",
            "results_kubescape.json",
            "-v",
        ]
        mock_subprocess_run.assert_called_once_with(
            expected_command, capture_output=True, check=True
        )
        mock_logger.error.assert_not_called()

    @patch("devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kubescape.kubescape_tool.subprocess.run", side_effect=subprocess.CalledProcessError(returncode=1, cmd="kubescape"))
    @patch("devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kubescape.kubescape_tool.logger")
    def test_execute_kubescape_failure(self, mock_logger, mock_subprocess_run):
        folders_to_scan = ["/path/to/folder1"]
        prefix = "kubescape"
        tool = self.kubescape_tool
        tool._execute_kubescape(folders_to_scan, prefix)

        expected_command = [
            "kubescape",
            "scan",
            shlex.quote("/path/to/folder1"),
            "--format",
            "json",
            "--format-version",
            "v2",
            "--output",
            "results_kubescape.json",
            "-v",
        ]
        mock_subprocess_run.assert_called_once_with(
            expected_command, capture_output=True, check=True
        )
        mock_logger.error.assert_called_once()

    @patch("builtins.open", new_callable=mock.mock_open, read_data='{"key": "value"}')
    def test_load_json_success(self, mock_file_open):
        result = self.kubescape_tool._load_json("json_name.json")
        self.assertEqual(result, {"key": "value"})
        mock_file_open.assert_called_once_with("json_name.json")

    def test_run_tool_empty_folders(self):
        config_tool = MagicMock()
        folders_to_scan = []
        platform_to_scan = "eks"

        findings_list, file_from_tool = self.kubescape_tool.run_tool(
            config_tool, folders_to_scan, platform_to_scan
        )
        
        self.assertEqual(findings_list, [])
        self.assertIsNone(file_from_tool)


    @patch('devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kubescape.kubescape_tool.distro.name', return_value='Ubuntu')
    @patch.object(KubescapeTool, '_install_tool')
    def test_select_operative_system_linux_ubuntu(self, mock_install_tool, mock_distro_name):
        executor = KubescapeTool()
        os_platform = 'Linux'
        base_url = 'http://example.com/'
        
        result = executor._select_operative_system(os_platform, base_url)
        
        mock_install_tool.assert_called_once_with('kubescape-ubuntu-latest', 'http://example.com/kubescape-ubuntu-latest')
        self.assertEqual(result, './kubescape-ubuntu-latest')

    @patch('devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kubescape.kubescape_tool.platform.system', return_value='Windows')
    @patch.object(KubescapeTool, '_install_tool_windows')
    def test_select_operative_system_windows(self, mock_install_tool_windows, mock_platform_system):
        executor = KubescapeTool()
        os_platform = 'Windows'
        base_url = 'http://example.com/'
        
        result = executor._select_operative_system(os_platform, base_url)
        
        mock_install_tool_windows.assert_called_once_with('kubescape-windows-latest.exe', 'http://example.com/kubescape-windows-latest.exe')
        self.assertEqual(result, '.\\kubescape-windows-latest.exe')

    @patch('devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kubescape.kubescape_tool.platform.system', return_value='Darwin')
    @patch.object(KubescapeTool, '_install_tool')
    def test_select_operative_system_darwin(self, mock_install_tool, mock_platform_system):
        executor = KubescapeTool()
        os_platform = 'Darwin'
        base_url = 'http://example.com/'
        
        result = executor._select_operative_system(os_platform, base_url)
        
        mock_install_tool.assert_called_once_with('kubescape-macos-latest', 'http://example.com/kubescape-macos-latest')
        self.assertEqual(result, './kubescape-macos-latest')

    def test_get_iac_context_from_results(self):
        path_file_results = "test_results.json"

        data = {
            "results": [
                {
                    "resourceID": "aws_s3_bucket.example",
                    "controls": [
                        {
                            "controlID": "C-001",
                            "name": "Ensure S3 bucket has access logging enabled",
                            "status": {"status": "failed"},
                            "rules": [
                                {
                                    "paths": [
                                        {
                                            "resourceID": "aws_s3_bucket.example",
                                            "fixPath": {"path": "main.tf"}
                                        }
                                    ]
                                }
                            ]
                        }
                    ]
                }
            ],
            "resources": [
                {
                    "resourceID": "aws_s3_bucket.example",
                    "source": {
                        "relativePath": "main.tf"
                    }
                }
            ],
            "summaryDetails": {
                "frameworks": [
                    {
                        "controls": {
                            "C-001": {
                                "scoreFactor": 7.5
                            }
                        }
                    }
                ]
            }
        }

        with patch("builtins.open", mock_open(read_data=json.dumps(data))) as mock_file:
            with patch('devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kubescape.kubescape_tool.KubescapeDeserealizator') as mock_deserealizator:
                mock_deserealizator_instance = mock_deserealizator.return_value
                mock_deserealizator_instance.extract_failed_controls.return_value = [
                    {"id": "C-0001", "where": "some-file.yaml", "description": "Privileged container"}
                ]
                mock_deserealizator_instance.get_severity_score.return_value = "High"
                
                self.kubescape_tool.get_iac_context_from_results(path_file_results)
                
                mock_file.assert_called_once_with(path_file_results, "r")
                mock_deserealizator_instance.extract_failed_controls.assert_called_once()
                mock_deserealizator_instance.get_severity_score.assert_called_once()