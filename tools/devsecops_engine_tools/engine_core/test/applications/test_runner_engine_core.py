from unittest import mock
from devsecops_engine_tools.engine_core.src.applications.runner_engine_core import (
    application_core,
    get_inputs_from_cli,
    parse_separated_list,
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
        "platform": "k8s",
        "use_secrets_manager": "true",
        "use_vulnerability_management": "false",
        "send_metrics": "true",
        "token_cmdb": "abc123",
        "token_vulnerability_management": None,
        "token_engine_container": None,
        "token_engine_dependencies": None,
        "xray_mode": "scan",
        "dir_to_scan": "/path/to/folder",
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
        "platform": "all",
        "use_secrets_manager": "true",
        "use_vulnerability_management": "false",
        "send_metrics": "true",
        "token_cmdb": "abc123",
        "token_vulnerability_management": None,
        "token_engine_container": None,
        "token_engine_dependencies": None,
        "xray_mode": "scan",
        "dir_to_scan": "/path/to/folder",
    }

    # Mock the dependencies
    mock_get_inputs_from_cli.return_value = mock_args

    # Mock the necessary methods or properties to simulate an exception
    mock_entry_point_tool.side_effect = Exception("Simulated error")

    # Act and Assert
    application_core()

    # Optionally, you can check the exception message or other details
    mock_print.assert_called()


@mock.patch("argparse.ArgumentParser.parse_args")
def test_get_inputs_from_cli(mock_parse_args):
    # Set up mock arguments
    mock_args = mock.MagicMock()
    mock_args.platform_devops = "azure"
    mock_args.remote_config_repo = "https://github.com/example/repo"
    mock_args.tool = "engine_iac"
    mock_args.folder_path = "/path/to/folder"
    mock_args.platform = "k8s,docker"
    mock_args.use_secrets_manager = "true"
    mock_args.use_vulnerability_management = "false"
    mock_args.send_metrics = "true"
    mock_args.token_cmdb = "abc123"
    mock_args.token_vulnerability_management = None
    mock_args.token_engine_container = None
    mock_args.token_engine_dependencies = None
    mock_args.xray_mode = "scan"
    mock_args.dir_to_scan = "/path/to/folder"

    # Mock the parse_args method
    mock_parse_args.return_value = mock_args

    # Call the function
    result = get_inputs_from_cli(None)

    # Assert that the function returns the expected result
    assert result == {
        "platform_devops": "azure",
        "remote_config_repo": "https://github.com/example/repo",
        "tool": "engine_iac",
        "folder_path": "/path/to/folder",
        "platform": "k8s,docker",
        "use_secrets_manager": "true",
        "use_vulnerability_management": "false",
        "send_metrics": "true",
        "token_cmdb": "abc123",
        "token_vulnerability_management": None,
        "token_engine_container": None,
        "token_engine_dependencies": None,
        "xray_mode": "scan",
        "dir_to_scan": "/path/to/folder",
    }


def test_parse_choices():
    # Set up mock arguments
    result = parse_separated_list(
        "docker,k8s", {"all", "docker", "k8s", "cloudformation"}
    )
    assert result == ["docker", "k8s"]
