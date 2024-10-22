from unittest import mock
import pytest
from unittest.mock import MagicMock, patch
from queue import Queue
from devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.checkov.checkov_tool import (
    CheckovTool,
)
import os


@pytest.fixture
def checkov_tool():
    return CheckovTool()

def test_create_config_file(checkov_tool):
    checkov_config = MagicMock()
    checkov_config.path_config_file = "/path/to/config/"
    checkov_config.config_file_name = "docker"
    checkov_config.dict_confg_file = {"key": "value"}

    with patch("builtins.open", create=True) as mock_open:
        checkov_tool.create_config_file(checkov_config)

        mock_open.assert_called_once_with(
            "/path/to/config/dockercheckov_config.yaml", "w"
        )
def test_configurate_external_checks_git(checkov_tool):
        json_data = {
            "SEARCH_PATTERN": ["AW", "NU"],
            "IGNORE_SEARCH_PATTERN": ["test"],
            "MESSAGE_INFO_ENGINE_IAC": "message test",
            "EXCLUSIONS_PATH": "Exclusions.json",
            "UPDATE_SERVICE_WITH_FILE_NAME_CFT": "false",
            "THRESHOLD": {
                "VULNERABILITY": {
                    "Critical": 10,
                    "High": 3,
                    "Medium": 20,
                    "Low": 30,
                },
                "COMPLIANCE": {"Critical": 4},
            },
            "CHECKOV": {
                "VERSION": "2.3.296",
                "USE_EXTERNAL_CHECKS_GIT": "True",
                "EXTERNAL_CHECKS_GIT": "rules",
                "EXTERNAL_GIT_SSH_HOST": "github",
                "EXTERNAL_GIT_PUBLIC_KEY_FINGERPRINT": "fingerprint",
                "USE_EXTERNAL_CHECKS_DIR": "False",
                "EXTERNAL_DIR_OWNER": "test",
                "EXTERNAL_DIR_REPOSITORY": "repository",
                "EXTERNAL_DIR_ASSET_NAME": "rules",
                "RULES": "",
                "APP_ID_GITHUB": "app_id",
                "INSTALATION_ID_GITHUB": "installation_id"
            },
        }



        result = checkov_tool.configurate_external_checks(
            json_data, None, "github_token:12234234"
        )

        assert result is None

        
def test_configurate_external_checks_dir(checkov_tool):
    json_data = {
        "SEARCH_PATTERN": ["AW", "NU"],
        "IGNORE_SEARCH_PATTERN": [
            "test",
        ],
        "MESSAGE_INFO_ENGINE_IAC": "message test",
        "EXCLUSIONS_PATH": "Exclusions.json",
        "UPDATE_SERVICE_WITH_FILE_NAME_CFT": "false",
        "THRESHOLD": {
            "VULNERABILITY": {
                "Critical": 10,
                "High": 3,
                "Medium": 20,
                "Low": 30,
            },
            "COMPLIANCE": {"Critical": 4},
        },
        "CHECKOV": {
            "VERSION": "2.3.296",
            "USE_EXTERNAL_CHECKS_GIT": "False",
            "EXTERNAL_CHECKS_GIT": "rules",
            "EXTERNAL_GIT_SSH_HOST": "github",
            "EXTERNAL_GIT_PUBLIC_KEY_FINGERPRINT": "fingerprint",
            "USE_EXTERNAL_CHECKS_DIR": "True",
            "EXTERNAL_DIR_OWNER": "test",
            "EXTERNAL_DIR_REPOSITORY": "repository",
            "EXTERNAL_DIR_ASSET_NAME": "rules",
            "RULES": "",
            "APP_ID_GITHUB": "app_id",
            "INSTALATION_ID_GITHUB": "installation_id"
        },
    }



    result = checkov_tool.configurate_external_checks(json_data,None, "ssh:2231231:123123")

    assert result is None

def test_retryable_install_package(checkov_tool):
    subprocess_mock = MagicMock()
    subprocess_mock.run.return_value.returncode = 1

    with patch("subprocess.run", return_value=subprocess_mock) as mock_run:
        response = checkov_tool.retryable_install_package("checkov", "2.3.96")

        mock_run.assert_called()
        assert response is False

def test_execute(checkov_tool):
    checkov_config = MagicMock()
    checkov_config.path_config_file = "/path/to/config/"
    checkov_config.config_file_name = "checkov_config"

    subprocess_mock = MagicMock()
    subprocess_mock.run.return_value.stdout = "Output"
    subprocess_mock.run.return_value.stderr = "Error"

    with patch("subprocess.run", return_value=subprocess_mock) as mock_run:
        checkov_tool.execute(checkov_config)

        mock_run.assert_called_once_with(
            "checkov --config-file /path/to/config/checkov_configcheckov_config.yaml",
            capture_output=True,
            text=True,
            shell=True,
            env=dict(os.environ),
        )

@patch(
    "devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.checkov.checkov_tool.CheckovTool.execute",
    autospec=True,
)
def test_async_scan(mock_checkov_tool, checkov_tool):
    checkov_config = MagicMock()
    checkov_config.path_config_file = "/path/to/config/"
    checkov_config.config_file_name = "checkov_config"

    output_queue = Queue()

    mock_checkov_tool.return_value = '{"key": "value"}'

    checkov_tool.async_scan(output_queue, checkov_config)

    assert output_queue.get() == [{"key": "value"}]

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
        checkov_tool, "async_scan", side_effect=output_queue.put
    ):
        result_scans, rules_run = checkov_tool.scan_folders(
            folders_to_scan, config_tool, agent_env, environment, "eks"
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
