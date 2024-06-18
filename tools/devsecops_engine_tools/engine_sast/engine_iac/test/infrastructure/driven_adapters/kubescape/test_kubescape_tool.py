import unittest
import subprocess
import logging
from unittest.mock import MagicMock
from unittest import mock
from devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kubescape.kubescape_tool import (
    KubescapeTool
)

logger = logging.getLogger()
logger.setLevel(logging.ERROR)
stream_handler = logging.StreamHandler()
logger.addHandler(stream_handler)


class TestKubescapeTool(unittest.TestCase):

    def setUp(self):
        self.kubescape_tool = KubescapeTool()

    @mock.patch('subprocess.run')
    def test_install_tool_linux_success(self, mock_run):

        mock_run.return_value = MagicMock(returncode=0, stderr="")

        kubescape_tool = KubescapeTool()
        kubescape_tool.install_tool_linux('1.0.0')

        mock_run.assert_called_once_with(
            "curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash -s -- -v v1.0.0",
            capture_output=True, shell=True, text=True
        )

    @mock.patch('subprocess.run')
    def test_install_tool_linux_failure(self, mock_run):

        mock_run.return_value = MagicMock(returncode=1, stderr="Simulated error")

        kubescape_tool = KubescapeTool()
        with self.assertLogs(logger, level='ERROR') as log:
            kubescape_tool.install_tool_linux('1.0.0')
            self.assertIn("Error during Kubescape installation on Linux: Simulated error", log.output[0])

        mock_run.assert_called_once_with(
            "curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash -s -- -v v1.0.0",
            capture_output=True, shell=True, text=True
        )

    @mock.patch('subprocess.run')
    def test_install_tool_windows_success(self, mock_run):

        mock_run.return_value = MagicMock(returncode=0, stderr="")

        kubescape_tool = KubescapeTool()
        kubescape_tool.install_tool_windows()

        mock_run.assert_called_once_with(
            "powershell -Command \"iwr -useb https://raw.githubusercontent.com/kubescape/kubescape/master/install.ps1 | iex\"",
            capture_output=True, shell=True, text=True
        )

    @mock.patch('subprocess.run')
    def test_install_tool_windows_failure(self, mock_run):

        mock_run.return_value = MagicMock(returncode=1, stderr="Simulated error")

        kubescape_tool = KubescapeTool()
        with self.assertLogs(logger, level='ERROR') as log:
            kubescape_tool.install_tool_windows()
            self.assertIn("Error during Kubescape installation on Windows: Simulated error", log.output[0])

        mock_run.assert_called_once_with(
            "powershell -Command \"iwr -useb https://raw.githubusercontent.com/kubescape/kubescape/master/install.ps1 | iex\"",
            capture_output=True, shell=True, text=True
        )

    @mock.patch("builtins.open", new_callable=mock.mock_open, read_data='{"key": "value"}')
    def test_load_json_success(self, mock_file):
        kubescape_tool = KubescapeTool()
        result = self.kubescape_tool.load_json()
        self.assertEqual(result, {"key": "value"})
        mock_file.assert_called_once_with("results_kubescape.json")

    @mock.patch('subprocess.run')
    def test_execute_kubescape_success(self, mock_run):

        mock_run.return_value = MagicMock(returncode=0)

        kubescape_tool = KubescapeTool()
        kubescape_tool.execute_kubescape(['folder1', 'folder2'])

        expected_calls = [
            unittest.mock.call(
                "kubescape scan framework nsa folder1 --format json --format-version v2 --output results_kubescape.json -v",
                capture_output=True, shell=True
            ),
            unittest.mock.call(
                "kubescape scan framework nsa folder2 --format json --format-version v2 --output results_kubescape.json -v",
                capture_output=True, shell=True
            )
        ]
        mock_run.assert_has_calls(expected_calls, any_order=True)

    @mock.patch('subprocess.run')
    def test_execute_kubescape_failure(self, mock_run):

        mock_run.side_effect = subprocess.CalledProcessError(returncode=1, cmd='kubescape scan')

        kubescape_tool = KubescapeTool()
        with self.assertLogs(logger, level='ERROR') as log:
            kubescape_tool.execute_kubescape(['folder1'])
            self.assertIn("Error during Kubescape execution: Command 'kubescape scan' returned non-zero exit status 1.", log.output[0])

        mock_run.assert_called_once_with(
            "kubescape scan framework nsa folder1 --format json --format-version v2 --output results_kubescape.json -v",
            capture_output=True, shell=True
        )

    def test_extract_failed_controls_no_failures(self):
        data = {
            "results": [
                {
                    "resourceID": "res1",
                    "controls": [
                        {"controlID": "ctrl1", "status": {"status": "passed"}}
                    ]
                }
            ],
            "resources": [
                {"resourceID": "res1", "source": {"relativePath": "path/to/res1"}}
            ],
            "summaryDetails": {
                "frameworks": []
            }
        }
        result = self.kubescape_tool.extract_failed_controls(data)
        self.assertEqual(result, [])

    def test_extract_failed_controls_with_failures(self):
        data = {
            "results": [
                {
                    "resourceID": "res1",
                    "controls": [
                        {"controlID": "ctrl1", "name": "Control 1", "status": {"status": "failed"}}
                    ]
                }
            ],
            "resources": [
                {"resourceID": "res1", "source": {"relativePath": "path/to/res1"}}
            ],
            "summaryDetails": {
                "frameworks": [{"controls": {"ctrl1": {"scoreFactor": 5}}}]
            }
        }
        result = self.kubescape_tool.extract_failed_controls(data)
        expected_result = [{
            "id": "ctrl1",
            "description": "Control 1",
            "where": "path/to/res1",
            "severity": "medium"
        }]
        self.assertEqual(result, expected_result)

    def test_get_severity_score_none(self):
        frameworks = [{"controls": {"control1": {"scoreFactor": 0.0}}}]
        result = self.kubescape_tool.get_severity_score(frameworks, "control1")
        self.assertEqual(result, "none")

    def test_get_severity_score_medium(self):
        frameworks = [{"controls": {"control1": {"scoreFactor": 5.0}}}]
        result = self.kubescape_tool.get_severity_score(frameworks, "control1")
        self.assertEqual(result, "medium")

    def test_get_severity_score_high(self):
        frameworks = [{"controls": {"control1": {"scoreFactor": 8.0}}}]
        result = self.kubescape_tool.get_severity_score(frameworks, "control1")
        self.assertEqual(result, "high")

    def test_get_severity_score_critical(self):
        frameworks = [{"controls": {"control1": {"scoreFactor": 9.5}}}]
        result = self.kubescape_tool.get_severity_score(frameworks, "control1")
        self.assertEqual(result, "critical")

    def test_run_tool_empty_folders(self):
        config_tool = MagicMock()
        folders_to_scan = []
        environment = "dev"
        platform = "eks"
        secret_tool = MagicMock()

        findings_list, file_from_tool = self.kubescape_tool.run_tool(
            config_tool, folders_to_scan, environment, platform, secret_tool
        )
        
        self.assertEqual(findings_list, [])
        self.assertEqual(file_from_tool, None)

    