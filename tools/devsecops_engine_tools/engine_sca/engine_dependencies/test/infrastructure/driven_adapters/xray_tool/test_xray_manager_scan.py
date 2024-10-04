from devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.xray_tool.xray_manager_scan import (
    XrayScan,
)

import pytest
from unittest.mock import patch, Mock
import os

import subprocess


@pytest.fixture
def xray_scan_instance():
    return XrayScan()


def test_install_tool_linux_success(xray_scan_instance):
    version = "2.52.8"
    prefix = "jf"
    with patch("subprocess.run") as mock_subprocess, patch(
        "requests.get"
    ) as mock_requests:
        mock_subprocess.return_value.returncode = 1
        mock_requests.return_value.content = b"fake_binary_data"
        xray_scan_instance.install_tool_linux(prefix, version)

        mock_subprocess.assert_called_with(
            ["chmod", "+x", prefix], check=True, stdout=-1, stderr=-1
        )
        mock_requests.assert_called_with(
            f"https://releases.jfrog.io/artifactory/jfrog-cli/v2-jf/{version}/jfrog-cli-linux-amd64/jf",
            allow_redirects=True,
        )


def test_install_tool_linux_failure(xray_scan_instance):
    version = "2.52.8"
    prefix = "jf"
    with patch("subprocess.run") as mock_subprocess, patch(
        "requests.get"
    ) as mock_requests, patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.xray_tool.xray_manager_scan.logger.error"
    ) as mock_logger_error:
        mock_subprocess.side_effect = [
            Mock(returncode=1),
            subprocess.CalledProcessError(returncode=1, cmd="chmod"),
        ]
        mock_requests.return_value.content = b"fake_binary_data"
        xray_scan_instance.install_tool_linux(prefix, version)
        mock_logger_error.assert_called_with(
            "Error during Jfrog Cli installation on Linux: Command 'chmod' returned non-zero exit status 1."
        )


def test_install_tool_windows_success(xray_scan_instance):
    version = "2.52.8"
    prefix = "jf"
    with patch("subprocess.run") as mock_subprocess, patch(
        "requests.get"
    ) as mock_requests:
        mock_subprocess.side_effect = subprocess.CalledProcessError(
            returncode=1, cmd="chmod"
        )
        mock_requests.return_value.content = b"fake_binary_data"
        xray_scan_instance.install_tool_windows(prefix, version)

        mock_requests.assert_called_with(
            f"https://releases.jfrog.io/artifactory/jfrog-cli/v2-jf/{version}/jfrog-cli-windows-amd64/jf.exe",
            allow_redirects=True,
        )


def test_install_tool_windows_failure(xray_scan_instance):
    version = "2.52.8"
    prefix = "jf"
    with patch("subprocess.run") as mock_subprocess, patch(
        "requests.get"
    ) as mock_requests, patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.xray_tool.xray_manager_scan.logger.error"
    ) as mock_logger_error:
        mock_subprocess.side_effect = subprocess.CalledProcessError(
            returncode=1, cmd="chmod"
        )
        mock_requests.side_effect = subprocess.CalledProcessError(
            returncode=1, cmd="chmod"
        )
        xray_scan_instance.install_tool_windows(prefix, version)

        mock_logger_error.assert_called_with(
            "Error while Jfrog Cli installation on Windows: Command 'chmod' returned non-zero exit status 1."
        )


def test_install_tool_darwin_success(xray_scan_instance):
    version = "2.52.8"
    prefix = "jf"
    with patch("subprocess.run") as mock_subprocess, patch(
        "requests.get"
    ) as mock_requests:
        mock_subprocess.return_value.returncode = 1
        mock_requests.return_value.content = b"fake_binary_data"
        xray_scan_instance.install_tool_darwin(prefix, version)

        mock_subprocess.assert_called_with(
            ["chmod", "+x", prefix], check=True, stdout=-1, stderr=-1
        )
        mock_requests.assert_called_with(
            f"https://releases.jfrog.io/artifactory/jfrog-cli/v2-jf/{version}/jfrog-cli-mac-386/jf",
            allow_redirects=True,
        )


def test_install_tool_darwin_failure(xray_scan_instance):
    version = "2.52.8"
    prefix = "jf"
    with patch("subprocess.run") as mock_subprocess, patch(
        "requests.get"
    ) as mock_requests, patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.xray_tool.xray_manager_scan.logger.error"
    ) as mock_logger_error:
        mock_subprocess.side_effect = [
            Mock(returncode=1),
            subprocess.CalledProcessError(returncode=1, cmd="chmod"),
        ]
        mock_requests.return_value.content = b"fake_binary_data"
        xray_scan_instance.install_tool_darwin(prefix, version)
        mock_logger_error.assert_called_with(
            "Error during Jfrog Cli installation on Darwin: Command 'chmod' returned non-zero exit status 1."
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
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.xray_tool.xray_manager_scan.logger.error"
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


def test_config_audit_scan(xray_scan_instance):
    with patch("os.path.join") as mock_pathjoin, patch(
        "os.path.exists"
    ) as mock_pathexists, patch("os.chmod") as mock_chmod, patch(
        "shutil.move"
    ) as mock_move:
        to_scan = "folder"
        mock_pathexists.side_effect = [True, False]

        xray_scan_instance.config_audit_scan(to_scan)

        assert mock_pathjoin.call_count == 1
        assert mock_pathexists.call_count == 1
        mock_chmod.assert_called_once()


def test_scan_dependencies_success(xray_scan_instance):
    with patch("subprocess.run") as mock_subprocess_run, patch(
        "json.dump"
    ) as mock_json_dump, patch("json.loads") as mock_json_loads, patch(
        "builtins.open"
    ) as mock_open, patch(
        "os.path.join"
    ) as mock_path_join, patch(
        "os.getcwd"
    ) as mock_os_getcwd:
        prefix = "jf"
        cwd = "working_dir"
        mode = "scan"
        to_scan = "target_file.tar"
        mock_subprocess_run.return_value = Mock(returncode=0)
        mock_os_getcwd.return_value = "working_dir"

        xray_scan_instance.scan_dependencies(prefix, cwd, mode, to_scan)

        mock_subprocess_run.assert_called_with(
            [
                prefix,
                "scan",
                "--format=json",
                f"{to_scan}",
            ],
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )


def test_scan_dependencies_failure(xray_scan_instance):
    with patch("subprocess.run") as mock_subprocess_run, patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.xray_tool.xray_manager_scan.logger.error"
    ) as mock_logger_error:
        prefix = "jf"
        cwd = "working_dir"
        mode = "scan"
        to_scan = "target_file.tar"
        mock_subprocess_run.return_value = Mock(
            returncode=1,
            stderr="Command 'xray scan' returned non-zero exit status 1.",
            stdout="",
        )

        xray_scan_instance.scan_dependencies(prefix, cwd, mode, to_scan)

        mock_logger_error.assert_called_with(
            "Error executing Xray scan: Command 'xray scan' returned non-zero exit status 1."
        )


def test_run_tool_dependencies_sca_linux(xray_scan_instance):
    with patch("platform.system") as mock_system, patch(
        "os.path.exists"
    ) as mock_pathexist, patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.xray_tool.xray_manager_scan.XrayScan.install_tool_linux"
    ) as mock_install_tool, patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.xray_tool.xray_manager_scan.XrayScan.config_server"
    ) as mock_config_server, patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.xray_tool.xray_manager_scan.XrayScan.scan_dependencies"
    ) as mock_scan_dependencies, patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.xray_tool.xray_manager_scan.XrayScan.config_audit_scan"
    ) as mock_config_audit_scan, patch(
        "os.path.expanduser"
    ) as mock_userpath:
        remote_config = {
            "XRAY": {"CLI_VERSION": "1.0"},
        }
        dict_args = {"xray_mode": "audit"}
        prefix = os.path.join("user_path", "jf")
        to_scan = "working_dir"
        secret_tool = {"token_xray": "token123"}
        exclusion = {}
        pipeline_name = "pipeline"
        mock_system.return_value = "Linux"
        mock_pathexist.return_value = True
        mock_userpath.return_value = "user_path"

        xray_scan_instance.run_tool_dependencies_sca(
            remote_config,
            dict_args,
            exclusion,
            pipeline_name,
            to_scan,
            secret_tool,
            None
        )

        mock_install_tool.assert_called_with(prefix, "1.0")
        mock_config_server.assert_called_with(prefix, "token123")
        mock_scan_dependencies.assert_called_with(
            prefix, "working_dir", dict_args["xray_mode"], ""
        )


def test_run_tool_dependencies_sca_windows(xray_scan_instance):
    with patch("platform.system") as mock_system, patch(
        "os.path.exists"
    ) as mock_pathexist, patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.xray_tool.xray_manager_scan.XrayScan.install_tool_windows"
    ) as mock_install_tool, patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.xray_tool.xray_manager_scan.XrayScan.config_server"
    ) as mock_config_server, patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.xray_tool.xray_manager_scan.XrayScan.scan_dependencies"
    ) as mock_scan_dependencies, patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.xray_tool.xray_manager_scan.XrayScan.config_audit_scan"
    ) as mock_config_audit_scan, patch(
        "os.path.expanduser"
    ) as mock_userpath:
        remote_config = {
            "XRAY": {"CLI_VERSION": "1.0"},
        }
        dict_args = {"xray_mode": "audit"}
        prefix = os.path.join("user_path", "jf.exe")
        to_scan = "working_dir"
        secret_tool = {"token_xray" : "token123"}
        exclusion = {}
        pipeline_name = "pipeline"
        mock_system.return_value = "Windows"
        mock_pathexist.return_value = True
        mock_userpath.return_value = "user_path"

        xray_scan_instance.run_tool_dependencies_sca(
            remote_config,
            dict_args,
            exclusion,
            pipeline_name,
            to_scan,
            secret_tool,
            None
        )

        mock_install_tool.assert_called_with(prefix, "1.0")
        mock_config_server.assert_called_with(prefix, "token123")

        mock_scan_dependencies.assert_called_with(
            prefix, "working_dir", dict_args["xray_mode"], ""
        )


def test_run_tool_dependencies_sca_darwin(xray_scan_instance):
    with patch("platform.system") as mock_system, patch(
        "os.path.exists"
    ) as mock_pathexist, patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.xray_tool.xray_manager_scan.XrayScan.install_tool_darwin"
    ) as mock_install_tool, patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.xray_tool.xray_manager_scan.XrayScan.config_server"
    ) as mock_config_server, patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.xray_tool.xray_manager_scan.XrayScan.scan_dependencies"
    ) as mock_scan_dependencies, patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.xray_tool.xray_manager_scan.XrayScan.config_audit_scan"
    ) as mock_config_audit_scan, patch(
        "os.path.expanduser"
    ) as mock_userpath:
        remote_config = {
            "XRAY": {"CLI_VERSION": "1.0"},
        }
        dict_args = {"xray_mode": "audit"}
        prefix = os.path.join("user_path", "jf")
        to_scan = "working_dir"
        token = None
        exclusion = {}
        pipeline_name = "pipeline"
        mock_system.return_value = "Darwin"
        mock_pathexist.return_value = True
        mock_userpath.return_value = "user_path"

        xray_scan_instance.run_tool_dependencies_sca(
            remote_config,
            dict_args,
            exclusion,
            pipeline_name,
            to_scan,
            token,
            "token_container"
        )

        mock_install_tool.assert_called_with(prefix, "1.0")
        mock_config_server.assert_called_with(prefix, "token_container")

        mock_scan_dependencies.assert_called_with(
            prefix, "working_dir", dict_args["xray_mode"], ""
        )
