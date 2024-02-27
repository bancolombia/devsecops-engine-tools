from devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.xray_tool.xray_manager_scan import (
    XrayScan,
)

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
            "Error during Jfrog Cli installation on Linux: Command 'chmod' returned non-zero exit status 1."
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
            "Error while Jfrog Cli installation on Windows: Command 'chmod' returned non-zero exit status 1."
        )


def test_config_server_success(xray_scan_instance):
    prefix = "prefix_test"
    token = "toke_test"
    with patch("subprocess.run") as mock_subprocess:
        mock_subprocess.side_effect = [
            Mock(
                returncode=0,
                stderr="15:43:29 [🔵Info] Importing server ID 'Artifactory'",
            ),
            Mock(returncode=0),
        ]
        xray_scan_instance.config_server(prefix, token)

        mock_subprocess.assert_called_with(
            [prefix, "c", "use", "Artifactory"],
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
                stderr="15:43:29 [🔵Info] Importing server ID 'Artifactory'",
            ),
            subprocess.CalledProcessError(returncode=1, cmd="chmod"),
        ]
        xray_scan_instance.config_server(prefix, token)

        mock_logger_error.assert_called_with(
            "Error during Xray Server configuration: Command 'chmod' returned non-zero exit status 1."
        )


def test_compress_and_mv_success(xray_scan_instance):
    with patch("os.path.exists") as mock_exists, patch(
        "os.remove"
    ) as mock_remove, patch("tarfile.open") as mock_tarfile_open:
        npm_modules = "/path/to/npm_modules"
        target_dir = "/path/to/target_dir"
        mock_exists.return_value = True
        xray_scan_instance.compress_and_mv(npm_modules, target_dir)

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
            "Error during npm_modules compression: Command 'opentar' returned non-zero exit status 1."
        )


def test_find_node_modules_finded(xray_scan_instance):
    with patch("os.walk") as mock_walk, patch("os.path.join") as mock_path_join:
        working_dir = "/path/to/working_dir"
        mock_walk.return_value = [
            (working_dir, ["dir1", "dir2"], ["file1.txt", "file2.json"]),
            (working_dir + "/dir1", [], ["file3.ear"]),
            (working_dir + "/node_modules", [], ["file4.war"]),
        ]
        xray_scan_instance.find_node_modules(working_dir)

        mock_path_join.assert_any_call


def test_find_node_modules_not_finded(xray_scan_instance):
    with patch("os.walk") as mock_walk, patch("os.path.join") as mock_path_join:
        working_dir = "/path/to/working_dir"
        mock_walk.return_value = [
            (working_dir, ["dir1", "dir2"], ["file1.txt", "file2.json"]),
            (working_dir + "/dir1", [], ["file3.ear"]),
            (working_dir + "/dir2", [], ["file4.war"]),
        ]
        xray_scan_instance.find_node_modules(working_dir)

        mock_path_join.assert_not_called


def test_find_artifacts(xray_scan_instance):
    with patch("shutil.copy2") as mock_copy2, patch("os.walk") as mock_walk, patch(
        "os.path.join"
    ) as mock_path_join:
        pattern = "\\.(jar|ear|war)$"
        working_dir = "/path/to/working_dir"
        target_dir = "/path/to/target_dir"
        excluded_dir = ""
        mock_walk.return_value = [
            ("/path/to/working_dir", ["dir1", "dir2"], ["file1.txt", "file2.json"]),
            ("/path/to/working_dir/dir1", [], ["file3.ear"]),
            ("/path/to/working_dir/dir2", [], ["file4.war"]),
        ]
        xray_scan_instance.find_artifacts(
            pattern, working_dir, target_dir, excluded_dir
        )

        mock_path_join.assert_any_call
        mock_copy2.assert_any_call


def test_scan_dependencies_success(xray_scan_instance):
    with patch("subprocess.run") as mock_subprocess_run, patch(
        "json.dump"
    ) as mock_json_dump, patch("json.loads") as mock_json_loads, patch(
        "builtins.open"
    ) as mock_open, patch(
        "os.path.join"
    ) as mock_path_join:
        prefix = "jf"
        target_dir_name = "target_dir"
        working_dir = "/path/to/working_dir"
        bypass_limits_flag = True
        mock_subprocess_run.side_effect = Mock(returncode=0)
        result = xray_scan_instance.scan_dependencies(
            prefix, target_dir_name, working_dir, bypass_limits_flag
        )

        mock_subprocess_run.assert_called_with(
            [
                prefix,
                "scan",
                "--format=json",
                "--bypass-archive-limits",
                f"{target_dir_name}/",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        mock_json_loads.assert_any_call
        mock_path_join.assert_called_with(working_dir, "scan_result.json")
        mock_open.assert_any_call
        mock_json_dump.assert_any_call


def test_scan_dependencies_failure(xray_scan_instance):
    with patch("subprocess.run") as mock_subprocess_run, patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.prisma_cloud.prisma_cloud_manager_scan.logger.error"
    ) as mock_logger_error:
        prefix = "jf"
        target_dir_name = "target_dir"
        working_dir = "/path/to/working_dir"
        bypass_limits_flag = False
        mock_subprocess_run.side_effect = subprocess.CalledProcessError(
            returncode=1, cmd="xray scan"
        )
        xray_scan_instance.scan_dependencies(
            prefix, target_dir_name, working_dir, bypass_limits_flag
        )

        mock_logger_error.assert_called_with(
            "Error executing jf scan: Command 'xray scan' returned non-zero exit status 1."
        )


def test_run_tool_dependencies_sca_linux(xray_scan_instance):
    remote_config = {
        "XRAY": {"CLI_VERSION": "1.0"},
    }
    token = "token123"
    working_dir = "/path/to/working_dir"
    skip_flag = False
    scan_flag = True
    bypass_limits_flag = False
    pattern = "\\.(jar|ear|war)$"

    with patch("platform.system") as mock_system, patch(
        "os.path.join"
    ) as mock_join, patch("os.path.exists") as mock_exists, patch(
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
    ) as mock_scan_dependencies, patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.xray_tool.xray_manager_scan.XrayScan.find_node_modules"
    ) as mock_find_node_modules:
        mock_system.return_value = "Linux"
        mock_join.side_effect = lambda *args: "/".join(args)
        mock_exists.return_value = True
        mock_find_node_modules.return_value = "/path/to/node_modules"
        result = xray_scan_instance.run_tool_dependencies_sca(
            remote_config,
            working_dir,
            skip_flag,
            scan_flag,
            bypass_limits_flag,
            pattern,
            token,
        )

        mock_install_tool_linux.assert_called_with("1.0")
        mock_config_server.assert_called_with("./jf", token)
        mock_rmtree.assert_any_call
        mock_makedirs.assert_any_call
        mock_find_node_modules.assert_called_with(working_dir)
        mock_compress_and_mv.assert_any_call
        mock_find_artifacts.assert_called_with(
            pattern,
            working_dir,
            working_dir + "/dependencies_to_scan",
            "/path/to/node_modules",
        )
        mock_scan_dependencies.assert_called_with(
            "./jf",
            working_dir + "/dependencies_to_scan",
            working_dir,
            bypass_limits_flag,
        )


def test_run_tool_dependencies_sca_windows(xray_scan_instance):
    remote_config = {
        "XRAY": {"CLI_VERSION": "1.0"},
    }
    token = "token123"
    working_dir = "/path/to/working_dir"
    skip_flag = False
    scan_flag = True
    bypass_limits_flag = False
    pattern = "\\.(jar|ear|war)$"

    with patch("platform.system") as mock_system, patch(
        "os.path.join"
    ) as mock_join, patch("os.path.exists") as mock_exists, patch(
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
    ) as mock_scan_dependencies, patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.xray_tool.xray_manager_scan.XrayScan.find_node_modules"
    ) as mock_find_node_modules:
        mock_system.return_value = "Windows"
        mock_join.side_effect = lambda *args: "/".join(args)
        mock_exists.return_value = True
        mock_find_node_modules.return_value = "/path/to/node_modules"
        result = xray_scan_instance.run_tool_dependencies_sca(
            remote_config,
            working_dir,
            skip_flag,
            scan_flag,
            bypass_limits_flag,
            pattern,
            token,
        )

        mock_install_tool_windows.assert_called_with("1.0")
        mock_config_server.assert_called_with("./jf.exe", token)
        mock_rmtree.assert_any_call
        mock_makedirs.assert_any_call
        mock_find_node_modules.assert_called_with(working_dir)
        mock_compress_and_mv.assert_any_call
        mock_find_artifacts.assert_called_with(
            pattern,
            working_dir,
            working_dir + "/dependencies_to_scan",
            "/path/to/node_modules",
        )
        mock_scan_dependencies.assert_called_with(
            "./jf.exe",
            working_dir + "/dependencies_to_scan",
            working_dir,
            bypass_limits_flag,
        )
