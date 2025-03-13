import subprocess
import unittest

from unittest.mock import patch
from devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kics.kics_tool import KicsTool
import os
import json
from unittest.mock import patch, MagicMock, mock_open


class TestKicsTool(unittest.TestCase):

    def setUp(self):
        self.kics_tool = KicsTool()

    @patch("devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kics.kics_tool.logger")
    def test_get_queries_success(self, mock_logger):
        config_tool = {
            "KICS": {
                "RULES": {
                    "RULES_PLATFORM1": {
                        "rule1": {"checkID": "check1"},
                        "rule2": {"checkID": "check2"}
                    },
                    "RULES_PLATFORM2": {
                        "rule3": {"checkID": "check3"},
                        "rule4": {"checkID": "check4"}
                    }
                }
            }
        }
        platform_to_scan = ["platform1", "platform2"]
        expected_queries = ["check1", "check2", "check3", "check4"]

        queries = self.kics_tool.get_queries(config_tool, platform_to_scan)

        self.assertEqual(queries, expected_queries)
        mock_logger.error.assert_not_called()

    @patch("devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kics.kics_tool.logger")
    def test_get_queries_with_exception(self, mock_logger):
        config_tool = {
            "KICS": {
                "RULES": {
                    "RULES_PLATFORM1": {
                        "rule1": {"checkID": "check1"},
                        "rule2": {"checkID": "check2"}
                    }
                }
            }
        }
        platform_to_scan = ["platform3"]

        queries = self.kics_tool.get_queries(config_tool, platform_to_scan)

        self.assertIsNone(queries)
        mock_logger.error.assert_called_with("Error writing queries file: 'RULES_PLATFORM3'")

    @patch("devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kics.kics_tool.subprocess.run")
    @patch("devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kics.kics_tool.logger")
    def test_execute_kics_failure(self, mock_logger, mock_subprocess_run):
        mock_subprocess_run.side_effect = subprocess.CalledProcessError(1, 'kics')

        folders_to_scan = ["folder1", "folder2"]
        prefix = "kics"
        platform_to_scan = ["platform1"]
        work_folder = "work_folder"
        os_platform = "Linux"
        queries = ["query1"]

        self.kics_tool.execute_kics(folders_to_scan, prefix, platform_to_scan, work_folder, os_platform, queries)

        mock_logger.error.assert_called_once_with("Error during KICS execution: Command 'kics' returned non-zero exit status 1.")

    @patch("builtins.open", new_callable=mock_open, read_data='{"key": "value"}')
    @patch("json.load", return_value={"key": "value"})
    def test_load_results_success(self, mock_json_load, mock_file):
        work_folder = "work_folder"
        result = self.kics_tool.load_results(work_folder)
        self.assertEqual(result, {"key": "value"})
        mock_file.assert_called_once_with(os.path.join(work_folder, "results.json"))
        mock_json_load.assert_called_once()

    @patch("builtins.open", new_callable=mock_open)
    @patch("json.load", side_effect=Exception("error"))
    @patch("devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kics.kics_tool.logger")
    def test_load_results_failure(self, mock_logger_error, mock_json_load, mock_file):
        work_folder = "work_folder"
        result = self.kics_tool.load_results(work_folder)
        self.assertIsNone(result)
        mock_file.assert_called_once_with(os.path.join(work_folder, "results.json"))
        mock_json_load.assert_called_once()
        mock_logger_error.error.assert_called_once_with("An error ocurred loading KICS results error")

    @patch("devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kics.kics_tool.subprocess.run")
    @patch("devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kics.kics_tool.logger")
    def test_validate_kics_success(self, mock_logger, mock_subprocess_run):
        mock_subprocess_run.return_value = MagicMock(returncode=0)

        command_prefix = "kics"
        result = self.kics_tool.validate_kics(command_prefix)

        self.assertTrue(result)
        mock_logger.error.assert_not_called()

    @patch("devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kics.kics_tool.subprocess.run")
    @patch("devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kics.kics_tool.logger")
    def test_validate_kics_failure(self, mock_logger, mock_subprocess_run):
        mock_subprocess_run.return_value = MagicMock(returncode=1, stderr="error")

        command_prefix = "kics"
        result = self.kics_tool.validate_kics(command_prefix)

        self.assertFalse(result)
        mock_logger.error.assert_called_once_with("KICS binary not valid: error")

    @patch("devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kics.kics_tool.subprocess.run", side_effect=Exception("Test exception"))
    @patch("devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kics.kics_tool.logger")
    def test_validate_kics_exception(self, mock_logger, mock_subprocess_run):
        command_prefix = "kics"
        result = self.kics_tool.validate_kics(command_prefix)

        self.assertFalse(result)
        mock_logger.error.assert_called_once_with("Error validating KICS binary: Test exception")

    @patch("requests.get")
    @patch("builtins.open", new_callable=mock_open)
    @patch("devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kics.kics_tool.logger")
    def test_download_success(self, mock_logger, mock_file, mock_requests_get):
        mock_requests_get.return_value.content = b"file content"
        file = "test_file"
        url = "http://example.com/test_file"

        self.kics_tool.download(file, url)

        mock_requests_get.assert_called_once_with(url)
        mock_file.assert_called_once_with(file, "wb")
        mock_file().write.assert_called_once_with(b"file content")
        mock_logger.error.assert_not_called()

    @patch("requests.get", side_effect=Exception("Test exception"))
    @patch("devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kics.kics_tool.logger")
    def test_download_failure(self, mock_logger, mock_requests_get):
        file = "test_file"
        url = "http://example.com/test_file"

        self.kics_tool.download(file, url)

        mock_requests_get.assert_called_once_with(url)
        mock_logger.error.assert_called_once_with("An error ocurred downloading test_file Test exception")

    if __name__ == '__main__':
        unittest.main()