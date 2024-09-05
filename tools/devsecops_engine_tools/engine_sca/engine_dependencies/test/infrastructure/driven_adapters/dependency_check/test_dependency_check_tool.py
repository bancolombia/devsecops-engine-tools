from devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.dependency_check.dependency_check_tool import (
    DependencyCheckTool,
)
from unittest.mock import patch, mock_open, MagicMock
from devsecops_engine_tools.engine_utilities.github.infrastructure.github_api import GithubApi
from devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.helpers.get_artifacts import GetArtifacts

import pytest
from unittest.mock import patch, Mock
import os
import json
import subprocess

@pytest.fixture
def dependency_check_scan_instance():
    return DependencyCheckTool()

@patch("builtins.open", new_callable=mock_open)
@patch("requests.get")
@patch.object(GithubApi, "unzip_file")
def test_download_tool(mock_unzip_file, mock_requests_get, mock_open, dependency_check_scan_instance):
    cli_version = "8.0.0"
    expected_url = f"https://github.com/jeremylong/DependencyCheck/releases/download/v{cli_version}/dependency-check-{cli_version}-release.zip"
    expected_zip_name = f"dependency_check_{cli_version}.zip"
    
    mock_response = MagicMock()
    mock_response.content = b"Fake content of the zip file"
    mock_requests_get.return_value = mock_response

    dependency_check_scan_instance.download_tool(cli_version)

    mock_requests_get.assert_called_once_with(expected_url, allow_redirects=True)

    mock_open.assert_called_once_with(expected_zip_name, "wb")

    mock_open().write.assert_called_once_with(b"Fake content of the zip file")

    mock_unzip_file.assert_called_once_with(expected_zip_name, None)

    assert mock_unzip_file.call_count == 1

@patch("subprocess.run")
@patch("os.getcwd")
@patch.object(DependencyCheckTool, "download_tool")
def test_install_tool(mock_download_tool, mock_getcwd, mock_subprocess_run, dependency_check_scan_instance):
    cli_version = "8.0.0"
    current_route = "/fake/path"
    bin_route = "dependency-check\\bin\\dependency-check.sh"
    expected_command_prefix = os.path.join(current_route, bin_route)

    mock_subprocess_run.side_effect = [
        MagicMock(returncode=1),
        MagicMock(returncode=1)
    ]

    mock_getcwd.return_value = current_route

    result = dependency_check_scan_instance.install_tool(cli_version)

    mock_subprocess_run.assert_any_call(
        ["which", "dependency-check.sh"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    mock_subprocess_run.assert_any_call(
        ["which", expected_command_prefix],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    mock_getcwd.assert_called()

    mock_download_tool.assert_called_once_with(cli_version)

    assert result == expected_command_prefix

@patch("subprocess.run")
@patch("os.getcwd")
def test_install_tool_already_installed(mock_getcwd, mock_subprocess_run, dependency_check_scan_instance):
    command_prefix = "dependency-check.sh"

    mock_subprocess_run.return_value = MagicMock(returncode=0)

    result = dependency_check_scan_instance.install_tool("8.0.0")

    mock_subprocess_run.assert_called_once_with(
        ["which", command_prefix],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    mock_getcwd.assert_not_called()

    assert result == command_prefix

@patch("subprocess.run")
@patch.object(DependencyCheckTool, "download_tool")
def test_install_tool_windows_first_try_success(mock_download_tool, mock_subprocess_run, dependency_check_scan_instance):
    cli_version = "8.0.0"
    command_prefix = "dependency-check.bat"

    mock_subprocess_run.return_value = MagicMock()

    result = dependency_check_scan_instance.install_tool_windows(cli_version)

    mock_subprocess_run.assert_called_once_with(
        [command_prefix, "--version"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    mock_download_tool.assert_not_called()

    assert result == command_prefix

@patch("subprocess.run")
@patch("os.getcwd")
@patch.object(DependencyCheckTool, "download_tool")
def test_install_tool_windows_second_try_success(mock_download_tool, mock_getcwd, mock_subprocess_run, dependency_check_scan_instance):
    cli_version = "8.0.0"
    current_route = "C:\\fake\\path"
    bin_route = "dependency-check\\bin\\dependency-check.bat"
    expected_command_prefix = os.path.join(current_route, bin_route)

    mock_subprocess_run.side_effect = [Exception(), MagicMock()]

    mock_getcwd.return_value = current_route

    result = dependency_check_scan_instance.install_tool_windows(cli_version)

    mock_subprocess_run.assert_any_call(
        [expected_command_prefix, "--version"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    mock_download_tool.assert_not_called()

    assert result == expected_command_prefix

@patch("subprocess.run")
@patch("os.getcwd")
@patch.object(DependencyCheckTool, "download_tool")
def test_install_tool_windows_third_try_success(mock_download_tool, mock_getcwd, mock_subprocess_run, dependency_check_scan_instance):
    cli_version = "8.0.0"
    current_route = "C:\\fake\\path"
    bin_route = "dependency-check\\bin\\dependency-check.bat"
    expected_command_prefix = os.path.join(current_route, bin_route)

    mock_subprocess_run.side_effect = [Exception(), Exception(), MagicMock()]

    mock_getcwd.return_value = current_route

    result = dependency_check_scan_instance.install_tool_windows(cli_version)

    assert mock_subprocess_run.call_count == 2

    mock_download_tool.assert_called_once_with(cli_version)

    mock_subprocess_run.assert_called_with(
        [expected_command_prefix, "--version"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    assert result == expected_command_prefix

@patch("subprocess.run")
def test_scan_dependencies_without_update(mock_subprocess_run, dependency_check_scan_instance):
    command_prefix = "dependency-check.sh"
    file_to_scan = "sample_project"
    nvd_api_key = "fake_api_key"
    update_nvd = False

    expected_command = [
        command_prefix,
        "--scan",
        file_to_scan,
        "--noupdate",
        "--format",
        "JSON"
    ]

    dependency_check_scan_instance.scan_dependencies(command_prefix, file_to_scan, nvd_api_key, update_nvd)

    mock_subprocess_run.assert_called_once_with(expected_command, capture_output=True)

@patch("subprocess.run")
def test_scan_dependencies_with_update(mock_subprocess_run, dependency_check_scan_instance):
    command_prefix = "dependency-check.sh"
    file_to_scan = "sample_project"
    nvd_api_key = "fake_api_key"
    update_nvd = True

    expected_command = [
        command_prefix,
        "--scan",
        file_to_scan,
        "--nvdApiKey",
        nvd_api_key,
        "--format",
        "JSON"
    ]

    dependency_check_scan_instance.scan_dependencies(command_prefix, file_to_scan, nvd_api_key, update_nvd)

    mock_subprocess_run.assert_called_once_with(expected_command, capture_output=True)

@patch("subprocess.run")
def test_scan_dependencies_throws_exception(mock_subprocess_run, dependency_check_scan_instance, caplog):
    command_prefix = "dependency-check.sh"
    file_to_scan = "sample_project"
    nvd_api_key = "fake_api_key"
    update_nvd = False

    mock_subprocess_run.side_effect = subprocess.CalledProcessError(1, 'cmd')

    dependency_check_scan_instance.scan_dependencies(command_prefix, file_to_scan, nvd_api_key, update_nvd)

    assert "Error executing OWASP dependency check scan" in caplog.text

@patch("platform.system")
@patch.object(DependencyCheckTool, "install_tool")
@patch.object(DependencyCheckTool, "install_tool_windows")
@patch.object(DependencyCheckTool, "scan_dependencies")
def test_select_operative_system_linux(mock_scan_dependencies, mock_install_tool_windows, mock_install_tool, mock_platform_system, dependency_check_scan_instance):
    cli_version = "8.0.0"
    file_to_scan = "sample_project"
    nvd_api_key = "fake_api_key"
    update_nvd = False

    mock_platform_system.return_value = "Linux"
    mock_install_tool.return_value = "/path/to/dependency-check.sh"

    dependency_check_scan_instance.select_operative_system(cli_version, file_to_scan, nvd_api_key, update_nvd)

    mock_install_tool.assert_called_once_with(cli_version)

    mock_install_tool_windows.assert_not_called()

    mock_scan_dependencies.assert_called_once_with(
        "/path/to/dependency-check.sh", file_to_scan, nvd_api_key, update_nvd
    )

@patch("platform.system")
@patch.object(DependencyCheckTool, "install_tool")
@patch.object(DependencyCheckTool, "install_tool_windows")
@patch.object(DependencyCheckTool, "scan_dependencies")
def test_select_operative_system_windows(mock_scan_dependencies, mock_install_tool_windows, mock_install_tool, mock_platform_system, dependency_check_scan_instance):
    cli_version = "8.0.0"
    file_to_scan = "sample_project"
    nvd_api_key = "fake_api_key"
    update_nvd = False

    mock_platform_system.return_value = "Windows"
    mock_install_tool_windows.return_value = "C:\\path\\to\\dependency-check.bat"

    dependency_check_scan_instance.select_operative_system(cli_version, file_to_scan, nvd_api_key, update_nvd)

    mock_install_tool_windows.assert_called_once_with(cli_version)

    mock_install_tool.assert_not_called()

    mock_scan_dependencies.assert_called_once_with(
        "C:\\path\\to\\dependency-check.bat", file_to_scan, nvd_api_key, update_nvd
    )

@patch("builtins.open", new_callable=mock_open, read_data='{"key": "value"}')
@patch("json.load")
def test_load_results_success(mock_json_load, mock_open_file, dependency_check_scan_instance):
    mock_json_load.return_value = {"key": "value"}

    result = dependency_check_scan_instance.load_results()

    mock_open_file.assert_called_once_with('dependency-check-report.json')

    mock_json_load.assert_called_once()

    assert result == {"key": "value"}

@patch("builtins.open", side_effect=FileNotFoundError)
@patch("json.load")
def test_load_results_file_not_found(mock_json_load, mock_open_file, dependency_check_scan_instance, caplog):

    result = dependency_check_scan_instance.load_results()

    mock_open_file.assert_called_once_with('dependency-check-report.json')

    mock_json_load.assert_not_called()

    assert "An error ocurred loading dependency-check results" in caplog.text

    assert result is None

@patch("builtins.open", new_callable=mock_open, read_data='{"key": "value"}')
@patch("json.load", side_effect=json.JSONDecodeError("Expecting value", "", 0))
def test_load_results_json_decode_error(mock_json_load, mock_open_file, dependency_check_scan_instance, caplog):

    result = dependency_check_scan_instance.load_results()

    mock_open_file.assert_called_once_with('dependency-check-report.json')

    mock_json_load.assert_called_once()

    assert "An error ocurred loading dependency-check results" in caplog.text

    assert result is None

@patch.object(GetArtifacts, "excluded_files")
@patch.object(GetArtifacts, "find_artifacts")
@patch.object(DependencyCheckTool, "select_operative_system")
@patch.object(DependencyCheckTool, "load_results")
def test_run_tool_dependencies_sca_success(
    mock_load_results,
    mock_select_operative_system,
    mock_find_artifacts,
    mock_excluded_files,
    dependency_check_scan_instance
):

    remote_config = {
        "DEPENDENCY_CHECK": {
            "CLI_VERSION": "8.0.0",
            "NVD_API_KEY": "fake_api_key",
            "UPDATE_NVD": True,
            "PACKAGES_TO_SCAN": ["package1", "package2"]
        }
    }
    dict_args = {}
    exclusion = {}
    pipeline_name = "test_pipeline"
    to_scan = ["file1", "file2"]
    token = "fake_token"

    mock_excluded_files.return_value = ".js|.py"
    mock_find_artifacts.return_value = ["filtered_file1", "filtered_file2"]
    mock_load_results.return_value = {"key": "value"}

    result = dependency_check_scan_instance.run_tool_dependencies_sca(
        remote_config, dict_args, exclusion, pipeline_name, to_scan, token
    )

    mock_excluded_files.assert_called_once_with(remote_config, pipeline_name, exclusion, "DEPENDENCY_CHECK")

    mock_find_artifacts.assert_called_once_with(
        to_scan, ".js|.py", remote_config["DEPENDENCY_CHECK"]["PACKAGES_TO_SCAN"]
    )

    mock_select_operative_system.assert_called_once_with(
        "8.0.0", ["filtered_file1", "filtered_file2"], "fake_api_key", True
    )

    mock_load_results.assert_called_once()
    assert result == {"key": "value"}

@patch.object(GetArtifacts, "excluded_files")
@patch.object(GetArtifacts, "find_artifacts")
@patch.object(DependencyCheckTool, "select_operative_system")
@patch.object(DependencyCheckTool, "load_results")
def test_run_tool_dependencies_sca_no_results(
    mock_load_results,
    mock_select_operative_system,
    mock_find_artifacts,
    mock_excluded_files,
    dependency_check_scan_instance
):
    remote_config = {
        "DEPENDENCY_CHECK": {
            "CLI_VERSION": "8.0.0",
            "NVD_API_KEY": "fake_api_key",
            "UPDATE_NVD": True,
            "PACKAGES_TO_SCAN": ["package1", "package2"]
        }
    }
    dict_args = {}
    exclusion = {}
    pipeline_name = "test_pipeline"
    to_scan = ["file1", "file2"]
    token = "fake_token"

    mock_excluded_files.return_value = ".js|.py"
    mock_find_artifacts.return_value = ["filtered_file1", "filtered_file2"]

    mock_load_results.return_value = None

    result = dependency_check_scan_instance.run_tool_dependencies_sca(
        remote_config, dict_args, exclusion, pipeline_name, to_scan, token
    )

    mock_excluded_files.assert_called_once_with(remote_config, pipeline_name, exclusion, "DEPENDENCY_CHECK")

    mock_find_artifacts.assert_called_once_with(
        to_scan, ".js|.py", remote_config["DEPENDENCY_CHECK"]["PACKAGES_TO_SCAN"]
    )

    mock_select_operative_system.assert_called_once_with(
        "8.0.0", ["filtered_file1", "filtered_file2"], "fake_api_key", True
    )

    mock_load_results.assert_called_once()
    assert result is None