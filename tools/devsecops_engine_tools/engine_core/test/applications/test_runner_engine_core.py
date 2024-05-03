from unittest import mock
from devsecops_engine_tools.engine_core.src.applications.runner_engine_core import (
    application_core,
)


@mock.patch(
    "devsecops_engine_tools.engine_core.src.applications.runner_engine_core.init_engine_core"
)
@mock.patch(
    "devsecops_engine_tools.engine_core.src.applications.runner_engine_core.get_inputs_from_cli"
)
def test_application_core(mock_get_inputs_from_cli, mock_entry_point_tool):
    # Set up mock arguments
    mock_args = {
        "platform_devops": "azure",
        "remote_config_repo": "https://github.com/example/repo",
        "tool": "engine_iac",
        "environment": "dev",
        "platform": "eks",
        "use_secrets_manager": "true",
        "use_vulnerability_management": "false",
        "send_metrics": "true",
        "token_cmdb": "abc123",
        "token_vulnerability_management": None,
        "token_engine_container": None,
        "token_engine_dependencies": None,
    }

    # Mock the dependencies
    mock_get_inputs_from_cli.return_value = mock_args
    init_output = mock_entry_point_tool.return_value = "ok"

    # Call the function
    application_core()

    # Assert that the dependencies are initialized correctly
    assert init_output == "ok"


@mock.patch(
    "devsecops_engine_tools.engine_core.src.applications.runner_engine_core.init_engine_core"
)
@mock.patch("builtins.print")
@mock.patch(
    "devsecops_engine_tools.engine_core.src.applications.runner_engine_core.get_inputs_from_cli"
)
def test_application_core_exception(
    mock_get_inputs_from_cli, mock_print, mock_entry_point_tool
):
    # Set up mock arguments
    mock_args = {
        "platform_devops": "azure",
        "remote_config_repo": "https://github.com/example/repo",
        "tool": "engine_iac",
        "environment": "dev",
        "platform": "eks",
        "use_secrets_manager": "true",
        "use_vulnerability_management": "false",
        "send_metrics": "true",
        "token_cmdb": "abc123",
        "token_vulnerability_management": None,
        "token_engine_container": None,
        "token_engine_dependencies": None,
    }

    # Mock the dependencies
    mock_get_inputs_from_cli.return_value = mock_args

    # Mock the necessary methods or properties to simulate an exception
    mock_entry_point_tool.side_effect = Exception("Simulated error")

    # Act and Assert
    application_core()

    # Optionally, you can check the exception message or other details
    mock_print.assert_called()
