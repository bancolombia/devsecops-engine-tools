from devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.xray_tool.xray_manager_scan import (
    XrayScan,
)

from devsecops_engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()

import pytest
from unittest.mock import mock_open, patch, Mock

import subprocess
import requests
import os

@pytest.fixture
def xray_scan_instance():
    return XrayScan()

def test_install_tool_linux_success(xray_scan_instance):
    version = "2.52.8"
    with patch("subprocess.run") as mock_subprocess, patch("requests.get") as mock_requests:
        mock_subprocess.return_value.returncode = 1
        mock_requests.return_value.content = b"fake_binary_data"
        xray_scan_instance.install_tool_linux(version)

        mock_subprocess.assert_called_with(["chmod", "+x", "./jf"], check=True, stdout=-1, stderr=-1)
        mock_requests.assert_called_with(f"https://releases.jfrog.io/artifactory/jfrog-cli/v2-jf/{version}/jfrog-cli-linux-amd64/jf", allow_redirects=True)

def test_install_tool_linux_failure(xray_scan_instance):
    version = "2.52.8"
    with patch("subprocess.run") as mock_subprocess, patch("requests.get") as mock_requests, patch("devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.prisma_cloud.prisma_cloud_manager_scan.logger.error") as mock_logger_error:
        mock_subprocess.side_effect = [
            Mock(returncode=1),
            subprocess.CalledProcessError(
                returncode=1, cmd="chmod"
            ),
        ]
        mock_requests.return_value.content = b"fake_binary_data"
        xray_scan_instance.install_tool_linux(version)
        mock_logger_error.assert_called_with("Error al instalar Jfrog Cli en Linux: Command 'chmod' returned non-zero exit status 1.")

def test_install_tool_windows_success(xray_scan_instance):
    version = "2.52.8"

    with patch("subprocess.run") as mock_subprocess, patch("requests.get") as mock_requests:
        mock_subprocess.side_effect = subprocess.CalledProcessError(
                returncode=1, cmd="chmod"
        )
        mock_requests.return_value.content = b"fake_binary_data"
        xray_scan_instance.install_tool_windows(version)

        mock_requests.assert_called_with(f"https://releases.jfrog.io/artifactory/jfrog-cli/v2-jf/{version}/jfrog-cli-windows-amd64/jf.exe", allow_redirects=True)

def test_install_tool_windows_failure(xray_scan_instance):
    version = "2.52.8"
    with patch("subprocess.run") as mock_subprocess, patch("requests.get") as mock_requests, patch("devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.prisma_cloud.prisma_cloud_manager_scan.logger.error") as mock_logger_error:
        mock_subprocess.side_effect = subprocess.CalledProcessError(
                returncode=1, cmd="chmod"
        )
        mock_requests.side_effect = subprocess.CalledProcessError(
                returncode=1, cmd="chmod"
        )
        xray_scan_instance.install_tool_windows(version)

        mock_logger_error.assert_called_with("Error al instalar Jfrog Cli en Windows: Command 'chmod' returned non-zero exit status 1.")

def test_config_server_success(xray_scan_instance):
    prefix="prefix_test"
    token="toke_test"
    with patch("subprocess.run") as mock_subprocess:
        mock_subprocess.side_effect = [
            Mock(returncode=0, stderr="15:43:29 [🔵Info] Importing server ID 'ArtifactoryBancolombia'"),
            Mock(returncode=0),
        ]
        xray_scan_instance.config_server(prefix, token)

        mock_subprocess.assert_called_with([prefix, "c", "use", 'ArtifactoryBancolombia'], check=True, stdout=-1, stderr=-1, text=True)

def test_config_server_failure(xray_scan_instance):
    prefix="prefix_test"
    token="toke_test"
    with patch("subprocess.run") as mock_subprocess, patch("devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.prisma_cloud.prisma_cloud_manager_scan.logger.error") as mock_logger_error:
        mock_subprocess.side_effect = [
            Mock(returncode=0, stderr="15:43:29 [🔵Info] Importing server ID 'ArtifactoryBancolombia'"),
            subprocess.CalledProcessError(
                returncode=1, cmd="chmod"
            ),
        ]
        xray_scan_instance.config_server(prefix, token)

        mock_logger_error.assert_called_with("Error al configurar xray server: Command 'chmod' returned non-zero exit status 1.")

def test_compress_and_mv_success(xray_scan_instance):
    with patch("shutil.rmtree") as mock_rmtree, patch("os.makedirs") as mock_makedirs, patch("os.path.exists") as mock_exists, patch("os.remove") as mock_remove, patch("tarfile.open") as mock_tarfile_open, patch("os.path.basename") as mock_basename:
        npm_modules = "/path/to/npm_modules"
        target_dir = "/path/to/target_dir"
        mock_exists.return_value = True
        xray_scan_instance.compress_and_mv(npm_modules, target_dir)

        mock_rmtree.assert_called_with(target_dir)
        mock_makedirs.assert_called_with(target_dir)
        mock_remove.assert_called_with(os.path.join(target_dir, "node_modules.tar"))
        mock_tarfile_open.assert_called_with(os.path.join(target_dir, "node_modules.tar"), "w")