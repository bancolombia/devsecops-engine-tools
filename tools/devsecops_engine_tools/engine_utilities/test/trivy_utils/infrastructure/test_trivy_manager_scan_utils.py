import pytest
import os
from unittest.mock import patch, MagicMock, Mock
from devsecops_engine_tools.engine_utilities.trivy_utils.infrastructure.driven_adapters.trivy_manager_scan_utils import TrivyManagerScanUtils


@pytest.fixture
def trivy_utils_instance():
    return TrivyManagerScanUtils()


def test_download_tool_success(trivy_utils_instance):
    """Test download_tool method in TrivyManagerScanUtils"""
    with patch("builtins.open") as mock_open, patch(
        "requests.get"
        ) as mock_request:

        trivy_utils_instance._download_tool("file", "url")

        assert mock_request.call_count == 1
        assert mock_open.call_count == 1


def test_download_tool_exception(trivy_utils_instance):
    """Test download_tool exception handling in TrivyManagerScanUtils"""
    with patch("requests.get") as mock_request:
        mock_request.side_effect = Exception("custom error")

        # The new implementation re-raises exceptions, so we expect it to propagate
        with pytest.raises(Exception) as exc_info:
            trivy_utils_instance._download_tool("file", "url")

        assert "custom error" in str(exc_info.value)
        mock_request.assert_called_once()


def test_install_tool_success(trivy_utils_instance):
    """Test _install_tool method in TrivyManagerScanUtils"""
    with patch("subprocess.run") as mock_run, patch(
        "tarfile.open"
    ) as mock_tar_open, patch(
        "devsecops_engine_tools.engine_utilities.trivy_utils.infrastructure.driven_adapters.trivy_manager_scan_utils.TrivyManagerScanUtils._download_tool"
    ) as mock_download:
        mock_run.return_value = Mock(returncode=1)

        trivy_utils_instance._install_tool("file", "url", "trivy")

        assert mock_tar_open.call_count == 1


def test_install_tool_exception(trivy_utils_instance):
    """Test _install_tool exception handling in TrivyManagerScanUtils"""
    with patch("subprocess.run") as mock_run, patch(
        "devsecops_engine_tools.engine_utilities.trivy_utils.infrastructure.driven_adapters.trivy_manager_scan_utils.logger.error"
        ) as mock_logger, patch(
        "devsecops_engine_tools.engine_utilities.trivy_utils.infrastructure.driven_adapters.trivy_manager_scan_utils.TrivyManagerScanUtils._download_tool"
        ) as mock_download:
        mock_run.return_value = Mock(returncode=1)
        mock_download.side_effect = Exception("custom error")

        trivy_utils_instance._install_tool("file", "url", "trivy")

        mock_logger.assert_called_with("Error installing trivy: custom error")


def test_install_tool_windows_success(trivy_utils_instance):
    """Test _install_tool_windows method in TrivyManagerScanUtils"""
    with patch("subprocess.run") as mock_run, patch(
        "zipfile.ZipFile"
    ) as mock_zipfile, patch(
        "devsecops_engine_tools.engine_utilities.trivy_utils.infrastructure.driven_adapters.trivy_manager_scan_utils.TrivyManagerScanUtils._download_tool"
    ) as mock_download:
        mock_run.side_effect = Exception()

        trivy_utils_instance._install_tool_windows("file", "url", "trivy.exe")

        assert mock_zipfile.call_count == 1


def test_install_tool_windows_exception(trivy_utils_instance):
    """Test _install_tool_windows exception handling in TrivyManagerScanUtils"""
    with patch("subprocess.run") as mock_run, patch(
        "devsecops_engine_tools.engine_utilities.trivy_utils.infrastructure.driven_adapters.trivy_manager_scan_utils.logger.error"
        ) as mock_logger, patch(
        "devsecops_engine_tools.engine_utilities.trivy_utils.infrastructure.driven_adapters.trivy_manager_scan_utils.TrivyManagerScanUtils._download_tool"
        ) as mock_download:
        mock_run.side_effect = Exception()
        mock_download.side_effect = Exception("custom error")

        trivy_utils_instance._install_tool_windows("file", "url", "trivy.exe")

        mock_logger.assert_called_with("Error installing trivy: custom error")


def test_identify_os_and_install_linux(trivy_utils_instance):
    """Test identify_os_and_install for Linux platform"""
    with patch("platform.system") as mock_platform, patch("platform.architecture") as mock_arch, patch(
        "devsecops_engine_tools.engine_utilities.trivy_utils.infrastructure.driven_adapters.trivy_manager_scan_utils.TrivyManagerScanUtils._install_tool"
    ) as mock_install:
        mock_platform.return_value = "Linux"
        mock_arch.return_value = ("64bit", "")
        mock_install.return_value = "./trivy"
        version = "1.2.3"

        result = trivy_utils_instance.identify_os_and_install(version)

        expected_file = f"trivy_{version}_Linux-64bit.tar.gz"
        expected_url = f"https://github.com/aquasecurity/trivy/releases/download/v{version}/{expected_file}"
        mock_install.assert_called_with(expected_file, expected_url, "trivy")
        assert result == "./trivy"

def test_identify_os_and_install_linux_arm64(trivy_utils_instance):
    """Test identify_os_and_install for Linux platform"""
    with patch("platform.system") as mock_platform, patch("platform.architecture") as mock_arch, patch(
        "devsecops_engine_tools.engine_utilities.trivy_utils.infrastructure.driven_adapters.trivy_manager_scan_utils.TrivyManagerScanUtils._install_tool"
    ) as mock_install, patch("platform.machine") as mock_machine:
        mock_platform.return_value = "Linux"
        mock_arch.return_value = ("64bit", "")
        mock_machine.return_value = "aarch64"
        mock_install.return_value = "./trivy"
        version = "1.2.3"

        result = trivy_utils_instance.identify_os_and_install(version)

        expected_file = f"trivy_{version}_Linux-ARM64.tar.gz"
        expected_url = f"https://github.com/aquasecurity/trivy/releases/download/v{version}/{expected_file}"
        mock_install.assert_called_with(expected_file, expected_url, "trivy")
        assert result == "./trivy"



def test_identify_os_and_install_darwin(trivy_utils_instance):
    """Test identify_os_and_install for macOS platform"""
    with patch("platform.system") as mock_platform, patch("platform.architecture") as mock_arch, patch(
        "devsecops_engine_tools.engine_utilities.trivy_utils.infrastructure.driven_adapters.trivy_manager_scan_utils.TrivyManagerScanUtils._install_tool"
    ) as mock_install:
        mock_platform.return_value = "Darwin"
        mock_arch.return_value = ("64bit", "")
        mock_install.return_value = "./trivy"
        version = "1.2.3"

        result = trivy_utils_instance.identify_os_and_install(version)

        expected_file = f"trivy_{version}_macOS-64bit.tar.gz"
        expected_url = f"https://github.com/aquasecurity/trivy/releases/download/v{version}/{expected_file}"
        mock_install.assert_called_with(expected_file, expected_url, "trivy")
        assert result == "./trivy"

def test_identify_os_and_install_darwin_arm64(trivy_utils_instance):
    """Test identify_os_and_install for macOS platform"""
    with patch("platform.system") as mock_platform, patch("platform.architecture") as mock_arch, patch(
        "devsecops_engine_tools.engine_utilities.trivy_utils.infrastructure.driven_adapters.trivy_manager_scan_utils.TrivyManagerScanUtils._install_tool"
    ) as mock_install, patch("platform.machine") as mock_machine:
        mock_platform.return_value = "Darwin"
        mock_arch.return_value = ("64bit", "")
        mock_machine.return_value = "arm64"
        mock_install.return_value = "./trivy"
        version = "1.2.3"

        result = trivy_utils_instance.identify_os_and_install(version)

        expected_file = f"trivy_{version}_macOS-ARM64.tar.gz"
        expected_url = f"https://github.com/aquasecurity/trivy/releases/download/v{version}/{expected_file}"
        mock_install.assert_called_with(expected_file, expected_url, "trivy")
        assert result == "./trivy"

def test_identify_os_and_install_windows(trivy_utils_instance):
    """Test identify_os_and_install for Windows platform"""
    with patch("platform.system") as mock_platform, patch("platform.architecture") as mock_arch, patch(
        "devsecops_engine_tools.engine_utilities.trivy_utils.infrastructure.driven_adapters.trivy_manager_scan_utils.TrivyManagerScanUtils._install_tool_windows"
    ) as mock_install:
        mock_platform.return_value = "Windows"
        mock_arch.return_value = ("64bit", "")
        mock_install.return_value = "./trivy.exe"
        version = "1.2.3"

        result = trivy_utils_instance.identify_os_and_install(version)

        expected_file = f"trivy_{version}_windows-64bit.zip"
        expected_url = f"https://github.com/aquasecurity/trivy/releases/download/v{version}/{expected_file}"
        mock_install.assert_called_with(expected_file, expected_url, "trivy.exe")
        assert result == "./trivy.exe"


def test_identify_os_and_install_unsupported(trivy_utils_instance):
    """Test identify_os_and_install for unsupported platform"""
    with patch("platform.system") as mock_platform, patch(
        "devsecops_engine_tools.engine_utilities.trivy_utils.infrastructure.driven_adapters.trivy_manager_scan_utils.logger.warning"
    ) as mock_logger:
        mock_platform.return_value = "UnsupportedOS"
        version = "1.2.3"

        result = trivy_utils_instance.identify_os_and_install(version)

        mock_logger.assert_called_with("UnsupportedOS is not supported.")
        assert result is None


def test_identify_os_and_install_blocked_version(trivy_utils_instance):
    """Test identify_os_and_install blocks compromised versions (CVE-2026-33634)"""
    with patch("devsecops_engine_tools.engine_utilities.trivy_utils.infrastructure.driven_adapters.trivy_manager_scan_utils.logger.error") as mock_logger:
        # Try to install a compromised version
        result = trivy_utils_instance.identify_os_and_install("0.69.4")

        # Should block the installation
        assert result is None
        mock_logger.assert_called_once()
        assert "CVE-2026-33634" in mock_logger.call_args[0][0]
        assert "compromised" in mock_logger.call_args[0][0]


def test_verify_checksum_success(trivy_utils_instance):
    """Test checksum verification with official checksums.txt"""
    import hashlib
    import tempfile
    import shutil

    mock_file_content = b"test binary content"
    expected_hash = hashlib.sha256(mock_file_content).hexdigest()

    mock_checksums = f"""f8766910f3909a75c603b7df630ff5639cf48d8eb0a2a26e4a20103a301e44f8 trivy_0.69.3_FreeBSD-64bit.tar.gz
{expected_hash} trivy_0.69.3_Linux-64bit.tar.gz
7e3924a974e912e57b4a99f65ece7931f8079584dae12eb7845024f97087bdfd trivy_0.69.3_Linux-ARM64.tar.gz
"""

    # Create temp dir and a file with exact expected name
    tmp_dir = tempfile.mkdtemp()
    tmp_path = os.path.join(tmp_dir, "trivy_0.69.3_Linux-64bit.tar.gz")
    with open(tmp_path, "wb") as f:
        f.write(mock_file_content)

    try:
        with patch("requests.get") as mock_get:
            mock_response = Mock()
            mock_response.text = mock_checksums
            mock_response.status_code = 200
            mock_response.raise_for_status = Mock()
            mock_get.return_value = mock_response

            result = trivy_utils_instance._verify_checksum(tmp_path)

            assert result is True
            mock_get.assert_called_once()
            assert "checksums.txt" in mock_get.call_args[0][0]
    finally:
        shutil.rmtree(tmp_dir)


def test_verify_checksum_mismatch(trivy_utils_instance):
    """Test checksum detection of compromised"""
    mock_checksums = """wronghash123 trivy_0.69.3_Linux-64bit.tar.gz
"""

    import tempfile
    import shutil

    # Create temp dir and a file with exact expected name
    tmp_dir = tempfile.mkdtemp()
    tmp_path = os.path.join(tmp_dir, "trivy_0.69.3_Linux-64bit.tar.gz")
    with open(tmp_path, "wb") as f:
        f.write(b"compromised content")

    try:
        with patch("requests.get") as mock_get, \
             patch("devsecops_engine_tools.engine_utilities.trivy_utils.infrastructure.driven_adapters.trivy_manager_scan_utils.logger.error") as mock_logger:
            mock_response = Mock()
            mock_response.text = mock_checksums
            mock_response.status_code = 200
            mock_response.raise_for_status = Mock()
            mock_get.return_value = mock_response

            result = trivy_utils_instance._verify_checksum(tmp_path)

            assert result is False
            assert "CHECKSUM MISMATCH" in mock_logger.call_args[0][0]
    finally:
        shutil.rmtree(tmp_dir)


def test_verify_checksum_no_checksums_file(trivy_utils_instance):
    """Test graceful handling when checksums.txt doesn't exist"""
    import tempfile
    import shutil

    # Create temp dir and a file with exact expected name
    tmp_dir = tempfile.mkdtemp()
    tmp_path = os.path.join(tmp_dir, "trivy_99.99.99_Linux-64bit.tar.gz")
    with open(tmp_path, "wb") as f:
        f.write(b"test content")

    try:
        with patch("requests.get") as mock_get, \
             patch("devsecops_engine_tools.engine_utilities.trivy_utils.infrastructure.driven_adapters.trivy_manager_scan_utils.logger.warning") as mock_logger:
            mock_response = Mock()
            mock_response.status_code = 404
            mock_get.return_value = mock_response

            result = trivy_utils_instance._verify_checksum(tmp_path)

            assert result is True  # Should allow when checksums unavailable
            assert "No official checksums available" in mock_logger.call_args[0][0]
    finally:
        shutil.rmtree(tmp_dir)
