import unittest
from unittest.mock import patch, mock_open, MagicMock
import os
import shutil
import subprocess
from devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.dependency_check.dependency_check_tool import (
    DependencyCheckTool,
)
from devsecops_engine_tools.engine_utilities.utils.utils import Utils


class TestDependencyCheckTool(unittest.TestCase):

    @patch("requests.get")
    @patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.dependency_check.dependency_check_tool.Utils"
    )
    @patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.dependency_check.dependency_check_tool.open",
        new_callable=mock_open,
    )
    @patch("os.path.join")
    @patch("os.path.expanduser")
    def test_download_tool(
        self, mock_expanduser, mock_path_join, mock_open, mock_utils, mock_requests_get
    ):
        mock_expanduser.return_value = "/mock/home"
        mock_path_join.return_value = "/mock/home/dependency_check_7.0.zip"
        mock_requests_get.return_value.content = b"Fake Zip Content"

        tool = DependencyCheckTool()

        tool.download_tool("7.0")

        mock_requests_get.assert_called_with(
            "https://github.com/jeremylong/DependencyCheck/releases/download/v7.0/dependency-check-7.0-release.zip",
            allow_redirects=True,
        )

        mock_expanduser.assert_called_once()

        mock_path_join.assert_called_with("/mock/home", "dependency_check_7.0.zip")

        mock_open.assert_called_with("/mock/home/dependency_check_7.0.zip", "wb")

        mock_open().write.assert_called_once_with(b"Fake Zip Content")

        mock_utils.return_value.unzip_file.assert_called_with(
            "/mock/home/dependency_check_7.0.zip", "/mock/home"
        )

    @patch("shutil.which")
    @patch("os.path.exists")
    @patch("os.path.join")
    @patch("os.path.expanduser")
    @patch("subprocess.run")
    @patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.dependency_check.dependency_check_tool.DependencyCheckTool.download_tool"
    )
    def test_install_tool_already_installed(
        self,
        mock_download_tool,
        mock_subprocess_run,
        mock_expanduser,
        mock_path_join,
        mock_exists,
        mock_which,
    ):
        mock_which.return_value = "/mock/path/dependency-check.sh"

        tool = DependencyCheckTool()

        result = tool.install_tool("7.0")

        mock_download_tool.assert_not_called()

        self.assertEqual(result, "dependency-check.sh")

    @patch("shutil.which")
    @patch("os.path.exists")
    @patch("os.path.join")
    @patch("os.path.expanduser")
    @patch("subprocess.run")
    @patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.dependency_check.dependency_check_tool.DependencyCheckTool.download_tool"
    )
    def test_install_tool_not_installed_linux(
        self,
        mock_download_tool,
        mock_subprocess_run,
        mock_expanduser,
        mock_path_join,
        mock_exists,
        mock_which,
    ):
        mock_which.side_effect = [None, None]
        mock_expanduser.return_value = "/mock/home"
        mock_path_join.return_value = (
            "/mock/home/dependency-check/bin/dependency-check.sh"
        )
        mock_exists.return_value = True

        tool = DependencyCheckTool()

        result = tool.install_tool("7.0")

        mock_download_tool.assert_called_once_with("7.0")

        mock_subprocess_run.assert_called_once_with(
            ["chmod", "+x", "/mock/home/dependency-check/bin/dependency-check.sh"],
            check=True,
        )

        self.assertEqual(result, "/mock/home/dependency-check/bin/dependency-check.sh")

    @patch("shutil.which")
    @patch("os.path.exists")
    @patch("os.path.join")
    @patch("os.path.expanduser")
    @patch("subprocess.run")
    @patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.dependency_check.dependency_check_tool.DependencyCheckTool.download_tool"
    )
    def test_install_tool_windows(
        self,
        mock_download_tool,
        mock_subprocess_run,
        mock_expanduser,
        mock_path_join,
        mock_exists,
        mock_which,
    ):
        mock_which.side_effect = [None, None]
        mock_expanduser.return_value = "/mock/home"
        mock_path_join.return_value = (
            "/mock/home/dependency-check/bin/dependency-check.bat"
        )
        mock_exists.return_value = True

        tool = DependencyCheckTool()

        result = tool.install_tool("7.0", is_windows=True)

        mock_download_tool.assert_called_once_with("7.0")

        mock_subprocess_run.assert_not_called()

        self.assertEqual(result, "/mock/home/dependency-check/bin/dependency-check.bat")

    @patch("shutil.which")
    @patch("os.path.exists")
    @patch("os.path.join")
    @patch("os.path.expanduser")
    @patch("subprocess.run")
    @patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.dependency_check.dependency_check_tool.DependencyCheckTool.download_tool"
    )
    @patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.dependency_check.dependency_check_tool.logger.error"
    )
    def test_install_tool_error_handling(
        self,
        mock_logger_error,
        mock_download_tool,
        mock_subprocess_run,
        mock_expanduser,
        mock_path_join,
        mock_exists,
        mock_which,
    ):
        mock_which.side_effect = [None, None]
        mock_expanduser.return_value = "/mock/home"
        mock_path_join.return_value = (
            "/mock/home/dependency-check/bin/dependency-check.sh"
        )
        mock_exists.return_value = True
        mock_subprocess_run.side_effect = Exception("chmod failed")

        tool = DependencyCheckTool()

        result = tool.install_tool("7.0")

        mock_download_tool.assert_called_once_with("7.0")

        mock_logger_error.assert_called_once_with(
            "Error installing OWASP dependency check: chmod failed"
        )

        self.assertIsNone(result)

    @patch("subprocess.run")
    def test_scan_dependencies_success(self, mock_subprocess_run):
        mock_subprocess_run.return_value = MagicMock()

        tool = DependencyCheckTool()

        tool.scan_dependencies("dependency-check.sh", "mock_file_to_scan", "token")

        mock_subprocess_run.assert_called_once_with(
            [
                "dependency-check.sh",
                "--format",
                "JSON",
                "--format",
                "XML",
                "--nvdApiKey",
                "token",
                "--scan",
                "mock_file_to_scan",
            ],
            capture_output=True,
            check=True,
        )

    @patch("subprocess.run")
    @patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.dependency_check.dependency_check_tool.logger.error"
    )
    def test_scan_dependencies_failure(self, mock_logger_error, mock_subprocess_run):
        mock_subprocess_run.side_effect = subprocess.CalledProcessError(
            returncode=1, cmd="dependency-check.sh"
        )

        tool = DependencyCheckTool()

        tool.scan_dependencies("dependency-check.sh", "mock_file_to_scan", "token")

        mock_logger_error.assert_called_once_with(
            "Error executing OWASP dependency check scan: Command 'dependency-check.sh' returned non-zero exit status 1."
        )

        mock_subprocess_run.assert_called_once_with(
            [
                "dependency-check.sh",
                "--format",
                "JSON",
                "--format",
                "XML",
                "--nvdApiKey",
                "token",
                "--scan",
                "mock_file_to_scan",
            ],
            capture_output=True,
            check=True,
        )

    @patch("platform.system")
    @patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.dependency_check.dependency_check_tool.DependencyCheckTool.install_tool"
    )
    def test_select_operative_system_linux(
        self, mock_install_tool, mock_platform_system
    ):
        mock_platform_system.return_value = "Linux"

        tool = DependencyCheckTool()

        result = tool.select_operative_system("7.0")

        mock_install_tool.assert_called_once_with("7.0", is_windows=False)

        self.assertEqual(result, mock_install_tool.return_value)

    @patch("platform.system")
    @patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.dependency_check.dependency_check_tool.DependencyCheckTool.install_tool"
    )
    def test_select_operative_system_windows(
        self, mock_install_tool, mock_platform_system
    ):
        mock_platform_system.return_value = "Windows"

        tool = DependencyCheckTool()

        tool.select_operative_system("7.0")

        mock_install_tool.assert_called_once_with("7.0", is_windows=True)

    @patch("platform.system")
    @patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.dependency_check.dependency_check_tool.DependencyCheckTool.install_tool"
    )
    def test_select_operative_system_darwin(
        self, mock_install_tool, mock_platform_system
    ):
        mock_platform_system.return_value = "Darwin"

        tool = DependencyCheckTool()

        tool.select_operative_system("7.0")

        mock_install_tool.assert_called_once_with("7.0", is_windows=False)

    @patch("platform.system")
    @patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.dependency_check.dependency_check_tool.logger.warning"
    )
    def test_select_operative_system_unsupported(
        self, mock_logger_warning, mock_platform_system
    ):
        mock_platform_system.return_value = "UnsupportedOS"

        tool = DependencyCheckTool()

        result = tool.select_operative_system("7.0")

        mock_logger_warning.assert_called_once_with("UnsupportedOS is not supported.")

        self.assertIsNone(result)

    @patch("shutil.which")
    def test_is_java_installed_found(self, mock_which):
        mock_which.return_value = "/usr/bin/java"

        tool = DependencyCheckTool()

        result = tool.is_java_installed()

        mock_which.assert_called_once_with("java")

        self.assertTrue(result)

    @patch("shutil.which")
    def test_is_java_installed_not_found(self, mock_which):
        mock_which.return_value = None

        tool = DependencyCheckTool()

        result = tool.is_java_installed()

        mock_which.assert_called_once_with("java")

        self.assertFalse(result)

    @patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.dependency_check.dependency_check_tool.DependencyCheckTool.is_java_installed"
    )
    @patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.dependency_check.dependency_check_tool.logger.error"
    )
    def test_run_tool_dependencies_sca_java_not_installed(
        self, mock_logger_error, mock_is_java_installed
    ):
        mock_is_java_installed.return_value = False

        tool = DependencyCheckTool()

        result = tool.run_tool_dependencies_sca(
            {}, {}, {}, "pipeline", "to_scan", "token", "token_engine_dependencies"
        )

        mock_logger_error.assert_called_once_with(
            "Java is not installed, please install it to run dependency check"
        )

        self.assertIsNone(result)

    @patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.dependency_check.dependency_check_tool.DependencyCheckTool.is_java_installed"
    )
    @patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.dependency_check.dependency_check_tool.GetArtifacts"
    )
    def test_run_tool_dependencies_sca_no_artifacts_found(
        self, mock_get_artifacts, mock_is_java_installed
    ):
        mock_is_java_installed.return_value = True

        mock_get_artifacts.return_value.find_artifacts.return_value = []

        tool = DependencyCheckTool()

        remote_config = {
            "DEPENDENCY_CHECK": {"CLI_VERSION": "7.0", "PACKAGES_TO_SCAN": "packages"}
        }

        result = tool.run_tool_dependencies_sca(
            remote_config,
            {},
            {},
            "pipeline",
            "to_scan",
            "token",
            "token_engine_dependencies",
        )

        self.assertIsNone(result)

    @patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.dependency_check.dependency_check_tool.DependencyCheckTool.is_java_installed"
    )
    @patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.dependency_check.dependency_check_tool.DependencyCheckTool.select_operative_system"
    )
    @patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.dependency_check.dependency_check_tool.DependencyCheckTool.scan_dependencies"
    )
    @patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.dependency_check.dependency_check_tool.DependencyCheckTool.search_result"
    )
    @patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.dependency_check.dependency_check_tool.GetArtifacts"
    )
    def test_run_tool_dependencies_sca_success(
        self,
        mock_get_artifacts,
        mock_search_result,
        mock_scan_dependencies,
        mock_select_operative_system,
        mock_is_java_installed,
    ):
        mock_is_java_installed.return_value = True

        mock_get_artifacts.return_value.excluded_files.return_value = "some_pattern"
        mock_get_artifacts.return_value.find_artifacts.return_value = [
            "artifact_to_scan"
        ]

        mock_select_operative_system.return_value = "dependency-check.sh"

        mock_search_result.return_value = {"key": "value"}

        tool = DependencyCheckTool()

        remote_config = {
            "DEPENDENCY_CHECK": {"CLI_VERSION": "7.0", "PACKAGES_TO_SCAN": "packages"}
        }

        result = tool.run_tool_dependencies_sca(
            remote_config,
            {},
            {},
            "pipeline",
            "to_scan",
            "token",
            "token_engine_dependencies",
        )

        mock_select_operative_system.assert_called_once_with("7.0")

        mock_scan_dependencies.assert_called_once_with(
            "dependency-check.sh", ["artifact_to_scan"], "token_engine_dependencies"
        )

        self.assertEqual(result, {"key": "value"})
