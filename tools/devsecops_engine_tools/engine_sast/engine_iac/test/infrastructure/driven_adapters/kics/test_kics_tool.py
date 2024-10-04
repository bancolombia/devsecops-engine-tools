import unittest
import subprocess
import logging
import os
from unittest.mock import MagicMock, patch, mock_open, call
from devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kics.kics_tool import (
    KicsTool, 
    KicsDeserealizator
)
from devsecops_engine_tools.engine_utilities.utils.utils import Utils

logger = logging.getLogger()
logger.setLevel(logging.ERROR)
stream_handler = logging.StreamHandler()
logger.addHandler(stream_handler)


class TestKicsTool(unittest.TestCase):

    def setUp(self):
        self.kics_tool = KicsTool()

    @patch("builtins.open", new_callable=mock_open)
    @patch('devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kics.kics_tool.requests.get')
    def test_download_tool_success(self, mock_get, mock_file):

        mock_response = MagicMock()
        mock_response.content = b'Test content'
        mock_get.return_value = mock_response

        url = "http://example.com/test"
        file = "testfile.bin"

        self.kics_tool.download(file, url)
        
        mock_get.assert_called_once_with(url)

        mock_file().write.assert_called_once_with(b'Test content')

    @patch('devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kics.kics_tool.subprocess.run')
    @patch('devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kics.kics_tool.logger')
    @patch.object(KicsTool, "download")
    def test_install_tool_already_installed(self, mock_download_tool, mock_logger, mock_subprocess_run):
        mock_installed = MagicMock()
        mock_installed.returncode = 0
        mock_subprocess_run.return_value = mock_installed
        command_prefix = "kics"

        file = "testfile.zip"
        url = "http://example.com/test"
        tool = self.kics_tool
        tool.install_tool(file, url, command_prefix)

        mock_subprocess_run.assert_called_once_with(
            ["which", "kics"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        mock_download_tool.assert_not_called()

        mock_logger.error.assert_not_called()

    @patch('devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kics.kics_tool.subprocess.run')
    @patch.object(KicsTool, "download")
    @patch.object(Utils, "unzip_file")
    def test_install_tool_not_installed(self, mock_unzip, mock_download, mock_subprocess):
        mock_subprocess.side_effect = [
            MagicMock(returncode=1),
            MagicMock()
        ]

        self.kics_tool.install_tool("kics.zip", "http://example.com/kics.zip", "kics")

        mock_download.assert_called_once_with("kics.zip", "http://example.com/kics.zip")
        mock_unzip.assert_called_once_with("kics.zip", "kics")
        mock_subprocess.assert_any_call(["which", "kics"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        mock_subprocess.assert_any_call(["chmod", "+x", "./kics/kics"])

    @patch("devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kics.kics_tool.subprocess.run")
    @patch("devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kics.kics_tool.logger")
    @patch.object(KicsTool, "download")
    def test_install_tool_windows_already_installed(self, mock_download_tool, mock_logger, mock_subprocess_run):
        mock_installed = MagicMock()
        mock_subprocess_run.return_value = mock_installed
        command_prefix = "kics"

        file = "testfile.zip"
        url = "http://example.com/test"
        tool = self.kics_tool
        tool.install_tool_windows(file, url, command_prefix)

        mock_subprocess_run.assert_called_once_with(
            ["kics", "version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        mock_download_tool.assert_not_called()

        mock_logger.error.assert_not_called()

    @patch("devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kics.kics_tool.subprocess.run", side_effect=Exception("Test exception"))
    @patch.object(Utils, 'unzip_file')
    @patch('devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kics.kics_tool.logger')
    @patch.object(KicsTool, "download")
    def test_install_tool_windows_not_installed(self, mock_download_tool, mock_logger, mock_unzip_file, mock_subprocess_run):
        mock_download_tool.return_value = None

        file = "testfile.zip"
        url = "http://example.com/test"
        tool = self.kics_tool
        command_prefix = "kics"
        tool.install_tool_windows(file, url, command_prefix)

        mock_subprocess_run.assert_called_once_with(
            ["kics", "version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        mock_download_tool.assert_called_once_with(file, url)
        mock_unzip_file.assert_called_once_with(file, "kics")
        mock_logger.error.assert_not_called()

    @patch('devsecops_engine_tools.engine_utilities.utils.utils.Utils')
    @patch("devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kics.kics_tool.subprocess.run", side_effect=Exception("Test exception"))
    @patch("devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kics.kics_tool.logger")
    @patch.object(KicsTool, "download", side_effect=Exception("Download exception"))
    def test_install_tool_windows_exception(self, mock_download_tool, mock_logger, mock_subprocess_run, mock_github_api):

        file = "testfile.zip"
        url = "http://example.com/test"
        tool = self.kics_tool
        command_prefix = "kics"
        tool.install_tool_windows(file, url, command_prefix)

        mock_subprocess_run.assert_called_once_with(
            ["kics", "version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        mock_download_tool.assert_called_once_with(file, url)

        mock_logger.error.assert_called_once_with("Error installing KICS: Download exception")

    @patch("devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kics.kics_tool.subprocess.run")
    @patch("devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kics.kics_tool.logger")
    def test_execute_kics_success(self, mock_logger, mock_subprocess_run):
        mock_subprocess_run.return_value = MagicMock()

        folders_to_scan = ["folder1", "folder2"]
        prefix = "kics"
        self.kics_tool.execute_kics(folders_to_scan, prefix)

        expected_calls = [
            call(
                ["kics", "scan", "-p", "folder1,folder2", "-q", "./kics_assets/assets", "--report-formats", "json", "-o", "./"],
                capture_output=True
            )
        ]
        mock_subprocess_run.assert_has_calls(expected_calls, any_order=False)

        mock_logger.error.assert_not_called()

    @patch('builtins.open', new_callable=mock_open, read_data='{"key": "value"}')
    @patch('json.load', return_value={"key": "value"})
    def test_load_results_success(self, mock_json_load, mock_file):
        result = self.kics_tool.load_results()
        self.assertEqual(result, {"key": "value"})
        mock_file.assert_called_once_with('results.json')
        mock_json_load.assert_called_once()

    @patch('builtins.open', new_callable=mock_open)
    @patch('json.load', side_effect=Exception("error"))
    @patch("devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kics.kics_tool.logger")
    def test_load_results_failure(self, mock_logger_error, mock_json_load, mock_file):
        result = self.kics_tool.load_results()
        self.assertIsNone(result)
        mock_file.assert_called_once_with('results.json')
        mock_json_load.assert_called_once()
        mock_logger_error.error.assert_called_once_with("An error ocurred loading KICS results error")

    @patch.object(KicsTool, 'install_tool')
    @patch.object(KicsTool, 'install_tool_windows')
    @patch.object(KicsTool, 'execute_kics')
    def test_select_operative_system_linux(self, mock_execute_kics, mock_install_tool_windows, mock_install_tool):
        mock_config_tool = {
            "KICS": {
                "KICS_LINUX": "http://example.com/kics_linux.zip",
                "PATH_KICS": "kics"
            }
        }

        mock_install_tool.return_value = "kics"

        self.kics_tool.select_operative_system("Linux", mock_config_tool, "kics")

        mock_install_tool.assert_called_once_with("kics_linux.zip", "http://example.com/kics_linux.zip", "kics")
        mock_install_tool_windows.assert_not_called()

    @patch.object(KicsTool, 'install_tool')
    @patch.object(KicsTool, 'install_tool_windows')
    @patch.object(KicsTool, 'execute_kics')
    def test_select_operative_system_windows(self, mock_execute_kics, mock_install_tool_windows, mock_install_tool):
        mock_config_tool = {
            "KICS": {
                "KICS_WINDOWS": "http://example.com/kics_windows.zip",
                "PATH_KICS": "kics"
            }
        }

        mock_install_tool_windows.return_value = "kics"

        self.kics_tool.select_operative_system("Windows", mock_config_tool, "kics")

        mock_install_tool_windows.assert_called_once_with("kics_windows.zip", "http://example.com/kics_windows.zip", "kics")
        mock_install_tool.assert_not_called()

    @patch.object(KicsTool, 'install_tool')
    @patch.object(KicsTool, 'install_tool_windows')
    @patch.object(KicsTool, 'execute_kics')
    def test_select_operative_system_darwin(self, mock_execute_kics, mock_install_tool_windows, mock_install_tool):
        mock_config_tool = {
            "KICS": {
                "KICS_MAC": "http://example.com/kics_mac.zip",
                "PATH_KICS": "kics"
            }
        }

        mock_install_tool.return_value = "kics"

        self.kics_tool.select_operative_system("Darwin", mock_config_tool, "kics")

        mock_install_tool.assert_called_once_with("kics_macos.zip", "http://example.com/kics_mac.zip", "kics")
        mock_install_tool_windows.assert_not_called()

    @patch.object(KicsTool, 'install_tool')
    @patch.object(KicsTool, 'install_tool_windows')
    @patch.object(KicsTool, 'execute_kics')
    @patch("devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kics.kics_tool.logger")
    def test_select_operative_system_unsupported(self, mock_logger, mock_execute_kics, mock_install_tool_windows, mock_install_tool):
        mock_config_tool = {
            "KICS": {
                "PATH_KICS": "kics"
            }
        }

        result = self.kics_tool.select_operative_system("UnsupportedOS", mock_config_tool, "kics")

        mock_install_tool.assert_not_called()
        mock_install_tool_windows.assert_not_called()
        mock_execute_kics.assert_not_called()
        mock_logger.warning.assert_called_once_with("UnsupportedOS is not supported.")
        self.assertEqual(result, ([], None))

    @patch.object(KicsTool, 'download')
    @patch.object(Utils, 'unzip_file')
    def test_get_assets(self, mock_unzip_file, mock_download):
        kics_version = "1.2.3"

        self.kics_tool.get_assets(kics_version)

        assets_url = f"https://github.com/Checkmarx/kics/releases/download/v{kics_version}/extracted-info.zip"
        mock_download.assert_called_once_with("assets_compressed.zip", assets_url)
        mock_unzip_file.assert_called_once_with("assets_compressed.zip", "kics_assets")

    @patch('platform.system', return_value='Linux')
    @patch.object(KicsTool, 'get_assets')
    @patch.object(KicsTool, 'select_operative_system')
    @patch.object(KicsTool, 'load_results', return_value={'data': 'results'})
    @patch.object(KicsDeserealizator, 'calculate_total_vulnerabilities', return_value=0)
    @patch.object(KicsTool, 'execute_kics')
    def test_run_tool_no_vulnerabilities(self, mock_execute_kics, mock_calc_vulns, mock_load_results, mock_select_os, mock_get_assets, mock_platform):
        mock_config_tool = {
            "KICS": {
                "VERSION": "1.2.3",
                "PATH_KICS": "mock/path/kics",
                "DOWNLOAD_KICS_ASSETS": True
            }
        }

        result, path = self.kics_tool.run_tool(mock_config_tool, ['folder1', 'folder2'], platform_to_scan='k8s')

        mock_get_assets.assert_called_once_with('1.2.3')
        mock_select_os.assert_called_once_with('Linux', mock_config_tool, 'mock/path/kics')
        mock_load_results.assert_called_once()
        mock_calc_vulns.assert_called_once_with({'data': 'results'})
        
        self.assertEqual(result, [])
        self.assertEqual(path, os.path.abspath("results.json"))

    @patch('platform.system', return_value='Linux')
    @patch.object(KicsTool, 'get_assets')
    @patch.object(KicsTool, 'select_operative_system')
    @patch.object(KicsTool, 'load_results', return_value={'data': 'results'})
    @patch.object(KicsDeserealizator, 'calculate_total_vulnerabilities', return_value=5)
    @patch.object(KicsDeserealizator, 'get_findings', return_value='filtered_results')
    @patch.object(KicsDeserealizator, 'get_list_finding', return_value=['finding1', 'finding2'])
    @patch.object(KicsTool, 'execute_kics')
    def test_run_tool_with_vulnerabilities(self, mock_execute_kics, mock_get_list_finding, mock_get_findings, mock_calc_vulns, mock_load_results, mock_select_os, mock_get_assets, mock_platform):
        mock_config_tool = {
            "KICS": {
                "VERSION": "1.2.3",
                "PATH_KICS": "mock/path/kics",
                "DOWNLOAD_KICS_ASSETS": True
            }
        }

        result, path = self.kics_tool.run_tool(mock_config_tool, ['folder1', 'folder2'], platform_to_scan='k8s')

        mock_get_assets.assert_called_once_with('1.2.3')
        mock_select_os.assert_called_once_with('Linux', mock_config_tool, 'mock/path/kics')
        mock_load_results.assert_called_once()
        mock_calc_vulns.assert_called_once_with({'data': 'results'})
        mock_get_findings.assert_called_once_with({'data': 'results'})
        mock_get_list_finding.assert_called_once_with('filtered_results')
        
        self.assertEqual(result, ['finding1', 'finding2'])
        self.assertEqual(path, os.path.abspath("results.json"))