import pytest
from unittest.mock import MagicMock
from devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway import DevopsPlatformGateway
from devsecops_engine_tools.engine_sca.engine_container.src.domain.usecases.handle_remote_config_patterns import HandleRemoteConfigPatterns


@pytest.fixture
def mock_devops_gateway():
    return MagicMock(spec=DevopsPlatformGateway)

@pytest.fixture
def handle_remote(mock_devops_gateway):
    return HandleRemoteConfigPatterns(mock_devops_gateway, {"remote_config_repo": "dummy_repo"})

def test_get_remote_config(mock_devops_gateway, handle_remote):
    mock_devops_gateway.get_remote_config.return_value = {"dummy_key": "dummy_value"}

    remote_config = handle_remote.get_remote_config("dummy_file_path")

    mock_devops_gateway.get_remote_config.assert_called_once_with("dummy_repo", "dummy_file_path")
    assert remote_config == {"dummy_key": "dummy_value"}

def test_get_variable(mock_devops_gateway, handle_remote):
    mock_devops_gateway.get_variable.return_value = "dummy_variable_value"

    variable = handle_remote.get_variable("dummy_variable")

    mock_devops_gateway.get_variable.assert_called_once_with("dummy_variable")
    assert variable == "dummy_variable_value"

def test_handle_skip_tool(handle_remote):
    exclusions = {
        "dummy_pipeline": {
            "SKIP_TOOL": 1
        }
    }

    result = handle_remote.handle_skip_tool(exclusions, "dummy_pipeline")

    assert result is True

def test_ignore_analysis_pattern_false(mock_devops_gateway, handle_remote):
    mock_devops_gateway.get_remote_config.return_value = {"IGNORE_SEARCH_PATTERN": "dummy_pattern"}
    mock_devops_gateway.get_variable.return_value = "dummy_pattern"

    result = handle_remote.ignore_analysis_pattern()

    mock_devops_gateway.get_remote_config.assert_called_once_with('dummy_repo', 'engine_sca/engine_container/ConfigTool.json')
    mock_devops_gateway.get_variable.assert_called_once_with("pipeline_name")

    assert result is False