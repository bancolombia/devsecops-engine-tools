from devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.xray_tool.xray_manager_scan import (
    XrayScan,
)

from devsecops_engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()

import pytest
from unittest.mock import mock_open, patch, Mock

import subprocess
import os


@pytest.fixture
def xray_scan_instance():
    return XrayScan()


def test_install_tool_linux_success(xray_scan_instance):
    version = "2.52.8"
    with patch("subprocess.run") as mock_subprocess, patch(
        "requests.get"
    ) as mock_requests:
        mock_subprocess.return_value.returncode = 1
        mock_requests.return_value.content = b"fake_binary_data"
        xray_scan_instance.install_tool_linux(version)

        mock_subprocess.assert_called_with(
            ["chmod", "+x", "./jf"], check=True, stdout=-1, stderr=-1
        )
        mock_requests.assert_called_with(
            f"https://releases.jfrog.io/artifactory/jfrog-cli/v2-jf/{version}/jfrog-cli-linux-amd64/jf",
            allow_redirects=True,
        )


def test_install_tool_linux_failure(xray_scan_instance):
    version = "2.52.8"
    with patch("subprocess.run") as mock_subprocess, patch(
        "requests.get"
    ) as mock_requests, patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.prisma_cloud.prisma_cloud_manager_scan.logger.error"
    ) as mock_logger_error:
        mock_subprocess.side_effect = [
            Mock(returncode=1),
            subprocess.CalledProcessError(returncode=1, cmd="chmod"),
        ]
        mock_requests.return_value.content = b"fake_binary_data"
        xray_scan_instance.install_tool_linux(version)
        mock_logger_error.assert_called_with(
            "Error al instalar Jfrog Cli en Linux: Command 'chmod' returned non-zero exit status 1."
        )


def test_install_tool_windows_success(xray_scan_instance):
    version = "2.52.8"

    with patch("subprocess.run") as mock_subprocess, patch(
        "requests.get"
    ) as mock_requests:
        mock_subprocess.side_effect = subprocess.CalledProcessError(
            returncode=1, cmd="chmod"
        )
        mock_requests.return_value.content = b"fake_binary_data"
        xray_scan_instance.install_tool_windows(version)

        mock_requests.assert_called_with(
            f"https://releases.jfrog.io/artifactory/jfrog-cli/v2-jf/{version}/jfrog-cli-windows-amd64/jf.exe",
            allow_redirects=True,
        )


def test_install_tool_windows_failure(xray_scan_instance):
    version = "2.52.8"
    with patch("subprocess.run") as mock_subprocess, patch(
        "requests.get"
    ) as mock_requests, patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.prisma_cloud.prisma_cloud_manager_scan.logger.error"
    ) as mock_logger_error:
        mock_subprocess.side_effect = subprocess.CalledProcessError(
            returncode=1, cmd="chmod"
        )
        mock_requests.side_effect = subprocess.CalledProcessError(
            returncode=1, cmd="chmod"
        )
        xray_scan_instance.install_tool_windows(version)

        mock_logger_error.assert_called_with(
            "Error al instalar Jfrog Cli en Windows: Command 'chmod' returned non-zero exit status 1."
        )


def test_config_server_success(xray_scan_instance):
    prefix = "prefix_test"
    token = "toke_test"
    with patch("subprocess.run") as mock_subprocess:
        mock_subprocess.side_effect = [
            Mock(
                returncode=0,
                stderr="15:43:29 [🔵Info] Importing server ID 'ArtifactoryBancolombia'",
            ),
            Mock(returncode=0),
        ]
        xray_scan_instance.config_server(prefix, token)

        mock_subprocess.assert_called_with(
            [prefix, "c", "use", "ArtifactoryBancolombia"],
            check=True,
            stdout=-1,
            stderr=-1,
            text=True,
        )


def test_config_server_failure(xray_scan_instance):
    prefix = "prefix_test"
    token = "toke_test"
    with patch("subprocess.run") as mock_subprocess, patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.prisma_cloud.prisma_cloud_manager_scan.logger.error"
    ) as mock_logger_error:
        mock_subprocess.side_effect = [
            Mock(
                returncode=0,
                stderr="15:43:29 [🔵Info] Importing server ID 'ArtifactoryBancolombia'",
            ),
            subprocess.CalledProcessError(returncode=1, cmd="chmod"),
        ]
        xray_scan_instance.config_server(prefix, token)

        mock_logger_error.assert_called_with(
            "Error al configurar xray server: Command 'chmod' returned non-zero exit status 1."
        )


def test_compress_and_mv_success(xray_scan_instance):
    with patch("shutil.rmtree") as mock_rmtree, patch(
        "os.makedirs"
    ) as mock_makedirs, patch("os.path.exists") as mock_exists, patch(
        "os.remove"
    ) as mock_remove, patch(
        "tarfile.open"
    ) as mock_tarfile_open, patch(
        "os.path.basename"
    ) as mock_basename:
        npm_modules = "/path/to/npm_modules"
        target_dir = "/path/to/target_dir"
        mock_exists.return_value = True
        xray_scan_instance.compress_and_mv(npm_modules, target_dir)

        mock_rmtree.assert_called_with(target_dir)
        mock_makedirs.assert_called_with(target_dir)
        mock_remove.assert_called_with(os.path.join(target_dir, "node_modules.tar"))
        mock_tarfile_open.assert_called_with(
            os.path.join(target_dir, "node_modules.tar"), "w"
        )


def test_compress_and_mv_failure(xray_scan_instance):
    with patch("shutil.rmtree") as mock_rmtree, patch(
        "os.makedirs"
    ) as mock_makedirs, patch("os.path.exists") as mock_exists, patch(
        "os.remove"
    ) as mock_remove, patch(
        "tarfile.open"
    ) as mock_tarfile_open, patch(
        "os.path.basename"
    ) as mock_basename, patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.prisma_cloud.prisma_cloud_manager_scan.logger.error"
    ) as mock_logger_error:
        npm_modules = "/path/to/npm_modules"
        target_dir = "/path/to/target_dir"
        mock_exists.return_value = True
        mock_tarfile_open.side_effect = subprocess.CalledProcessError(
            returncode=1, cmd="opentar"
        )
        xray_scan_instance.compress_and_mv(npm_modules, target_dir)

        mock_logger_error.assert_called_with(
            "Error al comprimir npm_modules: Command 'opentar' returned non-zero exit status 1."
        )


def test_find_artifacts(xray_scan_instance):
    with patch("shutil.rmtree") as mock_rmtree, patch(
        "os.makedirs"
    ) as mock_makedirs, patch("os.path.exists") as mock_exists, patch(
        "shutil.copy2"
    ) as mock_copy2, patch(
        "os.walk"
    ) as mock_walk:
        pattern = "\\.(jar|ear|war)$"
        working_dir = "/path/to/working_dir"
        target_dir = "/path/to/target_dir"
        mock_exists.return_value = True
        mock_walk.return_value = [
            ("/path/to/working_dir", ["dir1", "dir2"], ["file1.txt", "file2.json"]),
            ("/path/to/working_dir/dir1", [], ["file3.ear"]),
            ("/path/to/working_dir/dir2", [], ["file4.war"]),
        ]
        xray_scan_instance.find_artifacts(pattern, working_dir, target_dir)

        mock_exists.assert_called_with(target_dir)
        mock_rmtree.assert_called_with(target_dir)
        mock_makedirs.assert_called_with(target_dir)

        mock_copy2.assert_any_call


def test_scan_dependencies_success(xray_scan_instance):
    with patch("subprocess.run") as mock_subprocess_run, patch(
        "json.dump"
    ) as mock_json_dump, patch("json.loads") as mock_json_loads, patch(
        "builtins.open"
    ) as mock_open:
        prefix = "jf"
        target_dir_name = "target_dir"
        mock_subprocess_run.side_effect = Mock(returncode=0)
        result = xray_scan_instance.scan_dependencies(prefix, target_dir_name)

        mock_subprocess_run.assert_called_with(
            [prefix, "scan", "--format=json", f"./{target_dir_name}/"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        mock_json_loads.assert_any_call
        mock_open.assert_called_with("scan_result.json", "w")
        mock_json_dump.assert_any_call
        assert result == "scan_result.json"


def test_scan_dependencies_failure(xray_scan_instance):
    with patch("subprocess.run") as mock_subprocess_run, patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.prisma_cloud.prisma_cloud_manager_scan.logger.error"
    ) as mock_logger_error:
        prefix = "jf"
        target_dir_name = "target_dir"
        mock_subprocess_run.side_effect = subprocess.CalledProcessError(
            returncode=1, cmd="xray scan"
        )
        xray_scan_instance.scan_dependencies(prefix, target_dir_name)

        mock_logger_error.assert_called_with(
            "Error al ejecutar jf scan: Command 'xray scan' returned non-zero exit status 1."
        )


def test_run_tool_dependencies_sca_linux(xray_scan_instance):
    remote_config = {
        "XRAY": {"CLI_VERSION": "1.0"},
        "REGEX_EXPRESSION_EXTENSIONS": "\\.(jar|ear|war)$",
    }
    pipeline_name = ("pipeline1",)
    exclusions = {"pipeline1": {"XRAY": [{"files": ["war"]}]}}
    token = "token123"

    with patch("platform.system") as mock_system, patch(
        "os.getcwd"
    ) as mock_getcwd, patch("os.path.join") as mock_join, patch(
        "os.path.exists"
    ) as mock_exists, patch(
        "os.makedirs"
    ) as mock_makedirs, patch(
        "shutil.rmtree"
    ) as mock_rmtree, patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.xray_tool.xray_manager_scan.XrayScan.install_tool_linux"
    ) as mock_install_tool_linux, patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.xray_tool.xray_manager_scan.XrayScan.install_tool_windows"
    ) as mock_install_tool_windows, patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.xray_tool.xray_manager_scan.XrayScan.config_server"
    ) as mock_config_server, patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.xray_tool.xray_manager_scan.XrayScan.compress_and_mv"
    ) as mock_compress_and_mv, patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.xray_tool.xray_manager_scan.XrayScan.find_artifacts"
    ) as mock_find_artifacts, patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.xray_tool.xray_manager_scan.XrayScan.scan_dependencies"
    ) as mock_scan_dependencies:
        mock_system.return_value = "Linux"
        mock_getcwd.return_value = "/path/to/working_dir"
        mock_join.side_effect = lambda *args: "/".join(args)
        mock_exists.return_value = False
        result = xray_scan_instance.run_tool_dependencies_sca(
            remote_config, pipeline_name, exclusions, token
        )

        mock_install_tool_linux.assert_called_with("1.0")
        mock_config_server.assert_called_with("./jf", token)
        mock_find_artifacts.assert_called_with(
            "\\.(jar|ear|war)$",
            "/path/to/working_dir",
            "/path/to/working_dir/dependencies_to_scan",
        )
        mock_scan_dependencies.assert_called_with("./jf", "dependencies_to_scan")
        assert (result, "scan_result.json")


def test_run_tool_dependencies_sca_windows(xray_scan_instance):
    remote_config = {
        "XRAY": {"CLI_VERSION": "1.0"},
        "REGEX_EXPRESSION_EXTENSIONS": "\\.(jar|ear|war)$",
    }
    pipeline_name = ("pipeline1",)
    exclusions = {"pipeline1": {"XRAY": [{"files": ["war"]}]}}
    token = "token123"

    with patch("platform.system") as mock_system, patch(
        "os.getcwd"
    ) as mock_getcwd, patch("os.path.join") as mock_join, patch(
        "os.path.exists"
    ) as mock_exists, patch(
        "os.makedirs"
    ) as mock_makedirs, patch(
        "shutil.rmtree"
    ) as mock_rmtree, patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.xray_tool.xray_manager_scan.XrayScan.install_tool_linux"
    ) as mock_install_tool_linux, patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.xray_tool.xray_manager_scan.XrayScan.install_tool_windows"
    ) as mock_install_tool_windows, patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.xray_tool.xray_manager_scan.XrayScan.config_server"
    ) as mock_config_server, patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.xray_tool.xray_manager_scan.XrayScan.compress_and_mv"
    ) as mock_compress_and_mv, patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.xray_tool.xray_manager_scan.XrayScan.find_artifacts"
    ) as mock_find_artifacts, patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.xray_tool.xray_manager_scan.XrayScan.scan_dependencies"
    ) as mock_scan_dependencies:
        mock_system.return_value = "Windows"
        mock_getcwd.return_value = "/path/to/working_dir"
        mock_join.side_effect = lambda *args: "/".join(args)
        mock_exists.return_value = True
        result = xray_scan_instance.run_tool_dependencies_sca(
            remote_config, pipeline_name, exclusions, token
        )

        mock_install_tool_windows.assert_called_with("1.0")
        mock_config_server.assert_called_with("./jf.exe", token)
        mock_compress_and_mv.assert_called_with(
            "/path/to/working_dir/node_modules",
            "/path/to/working_dir/dependencies_to_scan",
        )
        mock_scan_dependencies.assert_called_with("./jf.exe", "dependencies_to_scan")
        assert (result, "scan_result.json")
