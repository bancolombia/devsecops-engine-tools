from devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.trivy_tool.trivy_manager_scan import (
    TrivyScan,
)

from unittest.mock import patch, MagicMock, Mock
import pytest


@pytest.fixture
def trivy_scan_instance():
    return TrivyScan()


def test_download_tool_success(trivy_scan_instance):
    with patch("builtins.open") as mock_open, patch(
        "requests.get"
        ) as mock_request:

        trivy_scan_instance.download_tool("file", "url")

        assert mock_request.call_count == 1
        assert mock_open.call_count == 1


def test_download_tool_exception(trivy_scan_instance):
    with patch("requests.get") as mock_request, patch(
            "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.trivy_tool.trivy_manager_scan.logger.error"
        ) as mocke_logger:
        mock_request.side_effect = Exception("custom error")

        trivy_scan_instance.download_tool("file", "url")

        mocke_logger.assert_called_with("Error downloading trivy: custom error")


def test_install_tool_success(trivy_scan_instance):
    with patch("subprocess.run") as mock_run, patch(
        "tarfile.open"
    ) as mock_tar_open:
        mock_run.return_value = Mock(returncode=1)
        trivy_scan_instance.download_tool = MagicMock()

        trivy_scan_instance.install_tool("file", "url")

        assert mock_tar_open.call_count == 1

def test_install_tool_exception(trivy_scan_instance):
    with patch("subprocess.run") as mock_run, patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.trivy_tool.trivy_manager_scan.logger.error"
        ) as mocke_logger:
        mock_run.return_value = Mock(returncode=1)
        trivy_scan_instance.download_tool = MagicMock()
        trivy_scan_instance.download_tool.side_effect = Exception("custom error")

        trivy_scan_instance.install_tool("file", "url")

        mocke_logger.assert_called_with("Error installing trivy: custom error")


def test_install_tool_windows_success(trivy_scan_instance):
    with patch("subprocess.run") as mock_run, patch(
        "zipfile.ZipFile"
    ) as mock_zipfile:
        mock_run.side_effect = Exception()
        trivy_scan_instance.download_tool = MagicMock()

        trivy_scan_instance.install_tool_windows("file", "url")

        assert mock_zipfile.call_count == 1


def test_install_tool_windows_exception(trivy_scan_instance):
    with patch("subprocess.run") as mock_run, patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.trivy_tool.trivy_manager_scan.logger.error"
        ) as mocke_logger:
        mock_run.side_effect = Exception()
        trivy_scan_instance.download_tool = MagicMock()
        trivy_scan_instance.download_tool.side_effect = Exception("custom error")

        trivy_scan_instance.install_tool_windows("file", "url")

        mocke_logger.assert_called_with("Error installing trivy: custom error")


def test_scan_image_success(trivy_scan_instance):
    with patch("subprocess.run") as mock_run, patch(
        "builtins.print"
    ) as mock_print:
        result = trivy_scan_instance.scan_image("prefix", "image_name", "result.json")

        assert mock_print.call_count == 1
        assert result == "result.json"


def test_scan_image_exception(trivy_scan_instance):
    with patch("subprocess.run") as mock_run, patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.trivy_tool.trivy_manager_scan.logger.error"
        ) as mocke_logger:
        mock_run.side_effect = Exception("custom error")

        trivy_scan_instance.scan_image("prefix", "image_name", "result.json")

        mocke_logger.assert_called_with("Error during image scan of image_name: custom error")


def test_run_tool_container_sca_linux(trivy_scan_instance):
    with patch("platform.system") as mock_platform:
        remote_config = {"TRIVY":{"TRIVY_VERSION": "1.2.3"}}
        mock_platform.return_value = "Linux"
        trivy_scan_instance.install_tool = MagicMock()
        trivy_scan_instance.scan_image = MagicMock()
        trivy_scan_instance.scan_image.return_value = "result.json"
        version = remote_config["TRIVY"]["TRIVY_VERSION"]
        file = f"trivy_{version}_Linux-64bit.tar.gz"
        base_url = f"https://github.com/aquasecurity/trivy/releases/download/v{version}/"

        result = trivy_scan_instance.run_tool_container_sca(remote_config, None, "image_name", "result.json")

        trivy_scan_instance.install_tool.assert_called_with(file, base_url+file)
        assert result == "result.json"


def test_run_tool_container_sca_darwin(trivy_scan_instance):
    with patch("platform.system") as mock_platform:
        remote_config = {"TRIVY":{"TRIVY_VERSION": "1.2.3"}}
        mock_platform.return_value = "Darwin"
        trivy_scan_instance.install_tool = MagicMock()
        trivy_scan_instance.scan_image = MagicMock()
        trivy_scan_instance.scan_image.return_value = "result.json"
        version = remote_config["TRIVY"]["TRIVY_VERSION"]
        file = f"trivy_{version}_macOS-64bit.tar.gz"
        base_url = f"https://github.com/aquasecurity/trivy/releases/download/v{version}/"

        result = trivy_scan_instance.run_tool_container_sca(remote_config, None, "image_name", "result.json")

        trivy_scan_instance.install_tool.assert_called_with(file, base_url+file)
        assert result == "result.json"


def test_run_tool_container_sca_windows(trivy_scan_instance):
    with patch("platform.system") as mock_platform:
        remote_config = {"TRIVY":{"TRIVY_VERSION": "1.2.3"}}
        mock_platform.return_value = "Windows"
        trivy_scan_instance.install_tool_windows = MagicMock()
        trivy_scan_instance.scan_image = MagicMock()
        trivy_scan_instance.scan_image.return_value = "result.json"
        version = remote_config["TRIVY"]["TRIVY_VERSION"]
        file = f"trivy_{version}_windows-64bit.zip"
        base_url = f"https://github.com/aquasecurity/trivy/releases/download/v{version}/"

        result = trivy_scan_instance.run_tool_container_sca(remote_config, None, "image_name", "result.json")

        trivy_scan_instance.install_tool_windows.assert_called_with(file, base_url+file)
        assert result == "result.json"

def test_run_tool_container_sca_none(trivy_scan_instance):
    with patch("platform.system") as mock_platform, patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.trivy_tool.trivy_manager_scan.logger.warning"
    ) as mock_logger:
        remote_config = {"TRIVY":{"TRIVY_VERSION": "1.2.3"}}
        mock_platform.return_value = "None"

        result = trivy_scan_instance.run_tool_container_sca(remote_config, None, "image_name", "result.json")

        mock_logger.assert_called_with("None is not supported.")
        assert result == None
