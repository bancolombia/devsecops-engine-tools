import unittest
from unittest.mock import patch, MagicMock, mock_open, call
import os
from devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.gitleaks.gitleaks_tool import (
    GitleaksTool
)

class TestGitleaksTool(unittest.TestCase):

    def setUp(self):
        # Arrange
        self.tool = GitleaksTool()
        self.agent_work_folder = "/path/to/work/folder"
        self.agent_temp_dir = "/path/to/temp/dir"
        self.repository_name = "test_repo"
        self.config_tool = {
            "gitleaks": {
                "VERSION": "8.20.0",
                "EXCLUDE_PATH": ["excluded_dir"],
                "NUMBER_THREADS": 2,
                "ALLOW_IGNORE_LEAKS": False,
                "ENABLE_CUSTOM_RULES" : False
            }
        }

    @patch("subprocess.run")
    @patch("re.search")
    def test_install_tool_windows(self, mock_search, mock_run):
        # Arrange
        mock_search.side_effect = [True, None, None]
        mock_run.return_value = MagicMock(stdout="command not found")
        
        with patch("requests.get") as mock_requests, patch("builtins.open", mock_open()) as mock_file, patch("devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.gitleaks.gitleaks_tool.Utils.unzip_file") as mock_unzip:
            mock_requests.return_value.content = b"compressed_data"

            # Act
            self.tool.install_tool("Windows_NT", self.agent_temp_dir, "8.0.0")

            # Assert
            mock_requests.assert_called_once_with(
                "https://github.com/gitleaks/gitleaks/releases/download/v8.0.0/gitleaks_8.0.0_windows_x64.zip",
                allow_redirects=True
            )
            mock_file.assert_called_once_with(f"{self.agent_temp_dir}/gitleaks_8.0.0_windows_x64.zip", "wb")
            mock_unzip.assert_called_once()

    @patch("subprocess.run")
    @patch("re.search")
    def test_install_tool_linux(self, mock_search, mock_run):
        # Arrange
        mock_search.side_effect = [None, True, None]
        mock_run.return_value = MagicMock(stdout="command not found")
        
        with patch("requests.get") as mock_requests, patch("builtins.open", mock_open()) as mock_file, patch("devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.gitleaks.gitleaks_tool.Utils.extract_targz_file") as mock_extract:
            mock_requests.return_value.content = b"compressed_data"

            # Act
            self.tool.install_tool("Linux", self.agent_temp_dir, "8.0.0")

            # Assert
            mock_requests.assert_called_once_with(
                "https://github.com/gitleaks/gitleaks/releases/download/v8.0.0/gitleaks_8.0.0_linux_x64.tar.gz",
                allow_redirects=True
            )
            mock_file.assert_called_once_with(f"{self.agent_temp_dir}/gitleaks_8.0.0_linux_x64.tar.gz", "wb")
            mock_extract.assert_called_once()

    @patch("subprocess.run")
    @patch("re.search")
    def test_install_tool_darwin(self, mock_search, mock_run):
        # Arrange
        mock_search.side_effect = [None, None, None]
        mock_run.return_value = MagicMock(stdout="command not found")
        
        with patch("requests.get") as mock_requests, patch("builtins.open", mock_open()) as mock_file, patch("devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.gitleaks.gitleaks_tool.Utils.extract_targz_file") as mock_extract:
            mock_requests.return_value.content = b"compressed_data"

            # Act
            self.tool.install_tool("Darwin", self.agent_temp_dir, "8.0.0")

            # Assert
            mock_requests.assert_called_once_with(
                "https://github.com/gitleaks/gitleaks/releases/download/v8.0.0/gitleaks_8.0.0_darwin_x64.tar.gz",
                allow_redirects=True
            )
            mock_file.assert_called_once_with(f"{self.agent_temp_dir}/gitleaks_8.0.0_darwin_x64.tar.gz", "wb")
            mock_extract.assert_called_once()

    @patch("subprocess.run")
    @patch("re.search")
    def test_tool_already_installed(self, mock_search, mock_run):
        # Arrange
        mock_search.side_effect = [None, True, True]
        mock_run.return_value = MagicMock(stdout="gitleaks version 8.20.0")

        # Act
        self.tool.install_tool("Linux", self.agent_temp_dir, "8.20.0")

        # Assert
        mock_run.assert_called_once_with(f"{self.agent_temp_dir}/gitleaks --version", capture_output=True, shell=True, text=True)
        mock_search.assert_any_call(r"8.20.0", "gitleaks version 8.20.0")

    @patch("os.path.exists")
    @patch("builtins.open", new_callable=mock_open, read_data='{"key": "value"}')
    def test_extract_json_data(self, mock_file, mock_exists):
        # Arrange
        mock_exists.return_value = True

        # Act
        result = self.tool._extract_json_data("/path/to/file.json")

        # Assert
        self.assertEqual(result, {"key": "value"})
        mock_file.assert_called_once_with("/path/to/file.json", "r", encoding="utf-8")

    @patch("os.path.exists")
    def test_extract_json_data_file_not_exists(self, mock_exists):
        # Arrange
        mock_exists.return_value = False

        # Act
        result = self.tool._extract_json_data("/path/to/nonexistent.json")

        # Assert
        self.assertEqual(result, [])

    @patch("builtins.open", new_callable=mock_open)
    def test_create_report(self, mock_file):
        # Arrange
        data = [{"key": "value"}]

        # Act
        self.tool._create_report("/path/to/report.json", data)

        # Assert
        mock_file.assert_called_once_with("/path/to/report.json", "w", encoding="utf-8")

    def test_check_path(self):
        # Arrange
        excluded_paths = ["excluded_dir"]

        # Act & Assert
        self.assertTrue(self.tool._check_path("some/excluded_dir/file.txt", excluded_paths))
        self.assertFalse(self.tool._check_path("some/other_dir/file.txt", excluded_paths))

    def test_add_flags(self):
        config_tool = {
            "gitleaks": {
                "ALLOW_IGNORE_LEAKS": False,
                "ENABLE_CUSTOM_RULES": True,
            }
        }
        expected_flags = [
            "--ignore-gitleaks-allow",
            "--config",
            f"{self.agent_work_folder}{os.sep}rules{os.sep}gitleaks{os.sep}gitleaks.toml"
        ]
        result = self.tool._add_flags(config_tool, "gitleaks", self.agent_work_folder)
        self.assertEqual(result, expected_flags)

    @patch("subprocess.run")
    @patch("os.path.join", side_effect=lambda *args: "/".join(args))
    @patch("devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.gitleaks.gitleaks_tool.GitleaksTool._extract_json_data", return_value=[{"leak": "found"}])
    def test_run_tool_secret_scan_single_file(self, mock_extract, mock_join, mock_run):
        # Act
        findings, finding_path = self.tool.run_tool_secret_scan(
            files=["file1.txt"],
            agent_os="Linux",
            agent_work_folder=self.agent_work_folder,
            repository_name=self.repository_name,
            config_tool=self.config_tool,
            secret_tool=None,
            secret_external_checks=None,
            agent_temp_dir=self.agent_temp_dir,
            tool="gitleaks"
        )

        # Assert
        self.assertEqual(findings, [{"leak": "found"}])
        self.assertEqual(finding_path, f"{self.agent_work_folder}/gitleaks_report.json")
        mock_run.assert_called_once()
    
    @patch("concurrent.futures.ThreadPoolExecutor")
    @patch("subprocess.run")
    @patch("os.path.join", side_effect=lambda *args: "/".join(args))
    @patch("devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.gitleaks.gitleaks_tool.GitleaksTool._extract_json_data", side_effect=lambda x: [{"leak": f"found in {x}"}])
    @patch("devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.gitleaks.gitleaks_tool.GitleaksTool._create_report")
    def test_run_tool_secret_scan_multiple_files(self, mock_create_report, mock_extract, mock_join, mock_run, mock_executor):
        # Arrange
        files = ["file1.txt", "file2.txt"]
        mock_executor.return_value.__enter__.return_value.submit.side_effect = lambda fn, *args, **kwargs: fn(*args, **kwargs)
        
        # Act
        findings, finding_path = self.tool.run_tool_secret_scan(
            files=files,
            agent_os="Linux",
            agent_work_folder=self.agent_work_folder,
            repository_name=self.repository_name,
            config_tool=self.config_tool,
            secret_tool=None,
            secret_external_checks=None,
            agent_temp_dir=self.agent_temp_dir,
            tool="gitleaks"
        )

        # Assert
        self.assertEqual(len(findings), 2)
        self.assertIn({"leak": "found in /path/to/work/folder/gitleaks_aux_report_file1.txt.json"}, findings)
        self.assertIn({"leak": "found in /path/to/work/folder/gitleaks_aux_report_file2.txt.json"}, findings)
        self.assertEqual(finding_path, f"{self.agent_work_folder}/gitleaks_report.json")
