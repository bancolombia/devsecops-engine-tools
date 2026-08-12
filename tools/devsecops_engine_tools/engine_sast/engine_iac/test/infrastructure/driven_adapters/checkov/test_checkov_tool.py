from unittest import mock
import pytest
from unittest.mock import MagicMock, Mock, mock_open, patch
from queue import Queue
from devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.checkov.checkov_tool import (
    CheckovTool,
)
import os
import requests
import subprocess

@pytest.fixture
def checkov_tool():
    return CheckovTool()

def test_create_config_file(checkov_tool):
    checkov_config = MagicMock()
    checkov_config.path_config_file = "/path/to/config/"
    checkov_config.config_file_name = "docker"
    checkov_config.dict_confg_file = {"key": "value"}

    with patch("builtins.open", create=True) as mock_open:
        checkov_tool._create_config_file(checkov_config)

        mock_open.assert_called_once_with(
            "/path/to/config/dockercheckov_config.yaml", "w"
        )

def test_retryable_install_package(checkov_tool):
    subprocess_mock = MagicMock()
    subprocess_mock.run.return_value.returncode = 1

    with patch("shutil.which") as mock_which, patch("subprocess.run", return_value=subprocess_mock) as mock_run:
        mock_which.side_effect = lambda x: None if x == "checkov" else "path/to/python"
        response = checkov_tool._retryable_install_package("checkov", "2.3.96")

        mock_run.assert_called()
        assert response is None

def test_execute(checkov_tool):
    checkov_config = MagicMock()
    checkov_config.path_config_file = "/path/to/config/"
    checkov_config.config_file_name = "checkov_config"
    checkov_config.env = None

    # Mock the subprocess.run return value properly
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "Output"
    mock_result.stderr = ""

    with patch("subprocess.run", return_value=mock_result) as mock_run:
        result = checkov_tool._execute(checkov_config, "checkov")

        mock_run.assert_called_once_with(
            "checkov --config-file /path/to/config/checkov_configcheckov_config.yaml",
            capture_output=True,
            text=True,
            shell=True,
            env=dict(os.environ),
        )
        assert result == "Output"

def test_execute_with_error(checkov_tool):
    checkov_config = MagicMock()
    checkov_config.path_config_file = "/path/to/config/"
    checkov_config.config_file_name = "checkov_config"
    checkov_config.env = None

    # Mock the subprocess.run return value with error
    mock_result = MagicMock()
    mock_result.returncode = 1
    mock_result.stdout = ""
    mock_result.stderr = "Some error occurred"

    with patch("subprocess.run", return_value=mock_result):
        result = checkov_tool._execute(checkov_config, "checkov")
        assert result == ""

def test_execute_with_warning(checkov_tool):
    checkov_config = MagicMock()
    checkov_config.path_config_file = "/path/to/config/"
    checkov_config.config_file_name = "checkov_config"
    checkov_config.env = None

    # Mock the subprocess.run return value with warning in stderr
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "Output"
    mock_result.stderr = "Warning: some error detected"

    with patch("subprocess.run", return_value=mock_result):
        result = checkov_tool._execute(checkov_config, "checkov")
        assert result == "Output"

@patch(
    "devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.checkov.checkov_tool.CheckovTool._execute",
    autospec=True,
)
def test_async_scan(mock_checkov_tool, checkov_tool):
    checkov_config = MagicMock()
    checkov_config.path_config_file = "/path/to/config/"
    checkov_config.config_file_name = "checkov_config"

    output_queue = Queue()

    mock_checkov_tool.return_value = '{"key": "value"}'

    checkov_tool._async_scan(output_queue, checkov_config, "checkov")

    assert output_queue.get() == [{"key": "value"}]

@patch(
    "devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.checkov.checkov_tool.CheckovTool._execute",
    autospec=True,
)
def test_async_scan_with_multiple_frameworks_list_output(mock_checkov_tool, checkov_tool):
    checkov_config = MagicMock()
    checkov_config.path_config_file = "/path/to/config/"
    checkov_config.config_file_name = "checkov_config"

    output_queue = Queue()

    mock_checkov_tool.return_value = (
        '[{"check_type": "terraform", "results": {"failed_checks": []}}, '
        '{"check_type": "terraform_plan", "results": {"failed_checks": []}}]'
    )

    checkov_tool._async_scan(output_queue, checkov_config, "checkov")

    result = output_queue.get()
    assert result == [
        {"check_type": "terraform", "results": {"failed_checks": []}},
        {"check_type": "terraform_plan", "results": {"failed_checks": []}},
    ]
    assert all(isinstance(entry, dict) for entry in result)

@patch(
    "devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.checkov.checkov_tool.CheckovTool._execute",
    autospec=True,
)
def test_async_scan_with_execution_error(mock_checkov_tool, checkov_tool):
    checkov_config = MagicMock()
    checkov_config.path_config_file = "/path/to/config/"
    checkov_config.config_file_name = "test_config"

    output_queue = Queue()

    # Mock _execute to raise an exception
    mock_checkov_tool.side_effect = Exception("Execution failed")

    checkov_tool._async_scan(output_queue, checkov_config, "checkov")

    result = output_queue.get()
    assert len(result) == 1
    assert "error" in result[0]
    assert "Execution failed" in result[0]["error"]
    assert result[0]["checkov_config"] == "test_config"

@patch(
    "devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.checkov.checkov_tool.CheckovTool._execute",
    autospec=True,
)
def test_async_scan_with_json_error(mock_checkov_tool, checkov_tool):
    checkov_config = MagicMock()
    checkov_config.path_config_file = "/path/to/config/"
    checkov_config.config_file_name = "test_config"

    output_queue = Queue()

    # Mock _execute to return invalid JSON
    mock_checkov_tool.return_value = "invalid json"

    checkov_tool._async_scan(output_queue, checkov_config, "checkov")

    result = output_queue.get()
    assert len(result) == 1
    assert "error" in result[0]
    assert "Failed to parse Checkov output as JSON" in result[0]["error"]
    assert result[0]["checkov_config"] == "test_config"

def test_scan_folders(checkov_tool):
    folders_to_scan = ["/path/to/folder"]
    config_tool = {
        "CHECKOV": {
            "USE_EXTERNAL_CHECKS_GIT": "False",
            "USE_EXTERNAL_CHECKS_DIR": "True",
            "EXTERNAL_DIR_OWNER": "test",
            "EXTERNAL_DIR_REPOSITORY": "repository",
            "EXTERNAL_CHECKS_GIT": "rules",
            "RULES": {
                "RULES_DOCKER": {"rule1": {"environment": {"dev": True}}},
                "RULES_K8S": {"rule2": {"environment": {"prod": True}}},
            }
        }
    }
    agent_env = MagicMock()
    environment = "dev"

    output_queue = Queue()
    output_queue.put([{"key": "value"}])

    with patch.object(
        checkov_tool, "_async_scan", side_effect=output_queue.put
    ):
        result_scans, rules_run = checkov_tool._scan_folders(
            folders_to_scan, config_tool, agent_env, environment, "eks", "checkov", {}
        )

    assert result_scans == []

def test_run_tool(checkov_tool):
    config_tool = MagicMock()
    folders_to_scan = ["/path/to/folder"]
    environment = "dev"
    platform = "eks"
    secret_tool = MagicMock()

    checkov_tool.configurate_external_checks = MagicMock(
        return_value="agent_env"
    )
    checkov_tool.scan_folders = MagicMock(return_value=[{"key": "value"}, []])
    checkov_tool.TOOL_CHECKOV = "CHECKOV"

    findings_list, file_from_tool = checkov_tool.run_tool(
        config_tool, folders_to_scan, environment, platform, secret_tool, secret_external_checks="github:token"
    )

    assert findings_list == []


@patch('requests.get')
@patch('builtins.open', new_callable=mock_open)
def test_download_tool_successful(mock_file, mock_get, checkov_tool):
    mock_response = Mock()
    mock_response.content = b"binary content"
    mock_get.return_value = mock_response
    file = "checkov.zip"
    url = "http://example.com/checkov.zip"

    checkov_tool._download_tool(file, url)

    mock_get.assert_called_once_with(url, allow_redirects=True)
    mock_file.assert_called_once_with(file, "wb")
    mock_file().write.assert_called_once_with(b"binary content")


@patch('subprocess.run')
@patch('devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.checkov.checkov_tool.CheckovTool._download_tool')
@patch('zipfile.ZipFile')
@patch('shutil.move')
def test_install_tool_unix(mock_move, mock_zipfile, mock_download_tool, mock_subprocess_run, checkov_tool):
    mock_subprocess_run.return_value.returncode = 1
    mock_zipfile.return_value.__enter__.return_value.extract = MagicMock()
    file = 'file.zip'
    url = 'http://example.com/file.zip'

    result = checkov_tool._install_tool_unix(file, url)

    mock_download_tool.assert_called_once_with(file, url)
    mock_zipfile.assert_called_once_with(file, 'r')
    mock_zipfile.return_value.__enter__.return_value.extract.assert_called_once_with(member='dist/checkov')
    mock_move.assert_called_once_with(os.path.join('dist', 'checkov'), 'checkov')
    assert result is None

@patch('subprocess.run')
@patch('devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.checkov.checkov_tool.CheckovTool._download_tool') 
@patch('zipfile.ZipFile')
@patch('shutil.move')
def test_install_tool_windows(mock_move, mock_zipfile, mock_download_tool, mock_subprocess_run, checkov_tool):
    mock_subprocess_run.side_effect = [subprocess.CalledProcessError(1, 'checkov.exe --version'), None]
    mock_zipfile.return_value.__enter__.return_value.extract = MagicMock()
    file = 'file.zip'
    url = 'http://example.com/file.zip'

    result = checkov_tool._install_tool_windows(file, url)

    mock_download_tool.assert_called_once_with(file, url)
    mock_zipfile.assert_called_once_with(file, 'r')
    mock_zipfile.return_value.__enter__.return_value.extract.assert_called_once_with(member='dist/checkov.exe')
    mock_move.assert_called_once_with(os.path.join('dist', 'checkov.exe'), 'checkov.exe')
    assert result is None