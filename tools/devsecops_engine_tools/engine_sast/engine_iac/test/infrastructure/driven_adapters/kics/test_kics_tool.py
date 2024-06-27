import unittest
import subprocess
import logging
from unittest.mock import MagicMock, patch, mock_open, call
from devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kics.kics_tool import (
    KicsTool
)

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

    @patch('devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kics.kics_tool.GithubApi')
    @patch('devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kics.kics_tool.subprocess.run')
    @patch('devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kics.kics_tool.logger')
    @patch.object(KicsTool, "download")
    def test_install_tool_already_installed(self, mock_download_tool, mock_logger, mock_subprocess_run, mock_github_api):
        mock_installed = MagicMock()
        mock_installed.returncode = 0
        mock_subprocess_run.return_value = mock_installed

        file = "testfile.zip"
        url = "http://example.com/test"
        tool = self.kics_tool
        tool.install_tool(file, url, mock_github_api)

        mock_subprocess_run.assert_called_once_with(
            ["which", "./kics_bin/kics"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        mock_download_tool.assert_not_called()

        mock_logger.error.assert_not_called()

    @patch('devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kics.kics_tool.GithubApi')
    @patch('devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kics.kics_tool.subprocess.run')
    @patch('devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kics.kics_tool.logger')
    @patch.object(KicsTool, "download")
    def test_install_tool_not_installed(self, mock_download_tool, mock_logger, mock_subprocess_run, mock_github_api):
        mock_installed = MagicMock()
        mock_installed.returncode = 1
        mock_subprocess_run.side_effect = [mock_installed, MagicMock()]

        file = "testfile.zip"
        url = "http://example.com/test"
        tool = self.kics_tool
        tool.install_tool(file, url, mock_github_api)

        self.assertEqual(mock_subprocess_run.call_count, 2)
        mock_subprocess_run.assert_any_call(
            ["which", "./kics_bin/kics"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        mock_subprocess_run.assert_any_call(["chmod", "+x", "./kics_bin/kics"])

        mock_download_tool.assert_called_once_with(file, url)

        mock_logger.error.assert_not_called()

    @patch('devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kics.kics_tool.GithubApi')
    @patch('devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kics.kics_tool.subprocess.run')
    @patch('devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kics.kics_tool.logger')
    @patch.object(KicsTool, "download")
    def test_install_tool_exception(self, mock_download_tool, mock_logger, mock_subprocess_run, mock_github_api):
        mock_installed = MagicMock()
        mock_installed.returncode = 1
        mock_subprocess_run.side_effect = [mock_installed, MagicMock()]

        mock_download_tool.side_effect = Exception("Test exception")

        file = "testfile.zip"
        url = "http://example.com/test"
        tool = self.kics_tool
        tool.install_tool(file, url, mock_github_api)

        mock_subprocess_run.assert_called_once_with(
            ["which", "./kics_bin/kics"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        mock_download_tool.assert_called_once_with(file, url)

        mock_logger.error.assert_called_once_with("Error installing KICS: Test exception")

    @patch('devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kics.kics_tool.GithubApi')
    @patch("devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kics.kics_tool.subprocess.run")
    @patch("devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kics.kics_tool.logger")
    @patch.object(KicsTool, "download")
    def test_install_tool_windows_already_installed(self, mock_download_tool, mock_logger, mock_subprocess_run, mock_github_api):
        mock_installed = MagicMock()
        mock_subprocess_run.return_value = mock_installed

        file = "testfile.zip"
        url = "http://example.com/test"
        tool = self.kics_tool
        tool.install_tool_windows(file, url, mock_github_api)

        mock_subprocess_run.assert_called_once_with(
            ["./kics_bin/kics.exe", "version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        mock_download_tool.assert_not_called()

        mock_logger.error.assert_not_called()

    @patch('devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kics.kics_tool.GithubApi')
    @patch("devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kics.kics_tool.subprocess.run", side_effect=Exception("Test exception"))
    @patch("devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kics.kics_tool.logger")
    @patch.object(KicsTool, "download")
    def test_install_tool_windows_not_installed(self, mock_download_tool, mock_logger, mock_subprocess_run, mock_github_api):
        mock_download_tool.return_value = None

        file = "testfile.zip"
        url = "http://example.com/test"
        tool = self.kics_tool
        tool.install_tool_windows(file, url, mock_github_api)

        mock_subprocess_run.assert_called_once_with(
            ["./kics_bin/kics.exe", "version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        mock_download_tool.assert_called_once_with(file, url)

        mock_logger.error.assert_not_called()

    @patch('devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kics.kics_tool.GithubApi')
    @patch("devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kics.kics_tool.subprocess.run", side_effect=Exception("Test exception"))
    @patch("devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kics.kics_tool.logger")
    @patch.object(KicsTool, "download", side_effect=Exception("Download exception"))
    def test_install_tool_windows_exception(self, mock_download_tool, mock_logger, mock_subprocess_run, mock_github_api):

        file = "testfile.zip"
        url = "http://example.com/test"
        tool = self.kics_tool
        tool.install_tool_windows(file, url, mock_github_api)

        mock_subprocess_run.assert_called_once_with(
            ["./kics_bin/kics.exe", "version"],
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
        prefix = "./kics_bin/kics"
        self.kics_tool.execute_kics(folders_to_scan, prefix)

        expected_calls = [
            call(
                ["./kics_bin/kics", "scan", "-p", "folder1", "-q", "./kics_assets/assets", "--report-formats", "json", "-o", "./"],
                capture_output=True
            ),
            call(
                ["./kics_bin/kics", "scan", "-p", "folder2", "-q", "./kics_assets/assets", "--report-formats", "json", "-o", "./"],
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

    def test_calculate_total_vulnerabilities(self):
        severity_counters = {
            "CRITICAL": 5,
            "HIGH": 10,
            "MEDIUM": 20,
            "LOW": 15
        }
        result = self.kics_tool.calculate_total_vulnerabilities(severity_counters)
        self.assertEqual(result, 50)

    @patch.object(KicsTool, 'load_results')
    @patch.object(KicsTool, 'calculate_total_vulnerabilities')
    def test_process_results(self, mock_calculate_total_vulnerabilities, mock_load_results):

        mock_load_results.return_value = {"severity_counters": {"CRITICAL": 5, "HIGH": 10, "MEDIUM": 20, "LOW": 15}}
        mock_calculate_total_vulnerabilities.return_value = 50

        result = self.kics_tool.process_results()

        self.assertEqual(result, 50)
        mock_load_results.assert_called_once()
        mock_calculate_total_vulnerabilities.assert_called_once_with({"CRITICAL": 5, "HIGH": 10, "MEDIUM": 20, "LOW": 15})

    @patch.object(KicsTool, 'load_results')
    @patch.object(KicsTool, 'calculate_total_vulnerabilities')
    def test_process_results_no_severity_counters(self, mock_calculate_total_vulnerabilities, mock_load_results):

        mock_load_results.return_value = {}
        mock_calculate_total_vulnerabilities.return_value = 0

        result = self.kics_tool.process_results()

        self.assertEqual(result, 0)
        mock_load_results.assert_called_once()
        mock_calculate_total_vulnerabilities.assert_called_once_with({})

    @patch.object(KicsTool, 'load_results')
    def test_get_findings(self, mock_load_results):
        mock_load_results.return_value = {
            "queries": [
                {
                    "severity": "HIGH",
                    "query_name": "SQL Injection",
                    "query_id": "Q123",
                    "files": [
                        {"file_name": "app.py"}
                    ]
                },
                {
                    "severity": "LOW",
                    "query_name": "Information Disclosure",
                    "query_id": "Q124",
                    "files": [
                        {"file_name": "config.yml"}
                    ]
                },
                {
                    "severity": "CRITICAL",
                    "query_name": "Remote Code Execution",
                    "query_id": "Q125",
                    "files": [
                        {"file_name": "server.js"}
                    ]
                },
                {
                    "severity": "INFO",
                    "query_name": "Commented Code",
                    "query_id": "Q126",
                    "files": [
                        {"file_name": "index.html"}
                    ]
                }
            ]
        }

        expected_results = [
            {
                "severity": "HIGH",
                "description": "SQL Injection",
                "file_name": "app.py",
                "id": "Q123"
            },
            {
                "severity": "LOW",
                "description": "Information Disclosure",
                "file_name": "config.yml",
                "id": "Q124"
            },
            {
                "severity": "CRITICAL",
                "description": "Remote Code Execution",
                "file_name": "server.js",
                "id": "Q125"
            }
        ]

        result = self.kics_tool.get_findings()

        self.assertEqual(result, expected_results)
        mock_load_results.assert_called_once()

    @patch.object(KicsTool, 'load_results')
    def test_get_findings_empty_queries(self, mock_load_results):
        mock_load_results.return_value = {"queries": []}

        result = self.kics_tool.get_findings()

        self.assertEqual(result, [])
        mock_load_results.assert_called_once()

    @patch.object(KicsTool, 'load_results')
    def test_get_findings_no_queries_key(self, mock_load_results):
        mock_load_results.return_value = {}

        result = self.kics_tool.get_findings()

        self.assertEqual(result, [])
        mock_load_results.assert_called_once()