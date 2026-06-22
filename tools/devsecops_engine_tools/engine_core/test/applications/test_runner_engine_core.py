import argparse
import runpy
from unittest import mock
import pytest
from devsecops_engine_tools.engine_core.src.applications.runner_engine_core import (
    application_core,
    get_inputs_from_cli,
    parse_separated_list,
    parse_choices,
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
        "remote_config_branch": "",
        "module": "engine_iac",
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
        "dast_file_path": "dast_file_path",
        "context": "false",
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
        "remote_config_branch": "",
        "module": "engine_iac",
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
    mock_args.remote_config_branch = ""
    mock_args.remote_config_source = "azure"
    mock_args.module = "engine_iac"
    mock_args.tool = None
    mock_args.folder_path = "/path/to/folder"
    mock_args.terraform_repo_root = "/path/to/terraform/repo/root"
    mock_args.platform = "k8s,docker"
    mock_args.use_secrets_manager = "true"
    mock_args.use_vulnerability_management = "false"
    mock_args.send_metrics = "true"
    mock_args.token_cmdb = "abc123"
    mock_args.token_vulnerability_management = None
    mock_args.token_engine_container = None
    mock_args.token_engine_dependencies = None
    mock_args.token_external_checks = None
    mock_args.xray_mode = "scan"
    mock_args.image_to_scan = "image"
    mock_args.dast_file_path = "dast_file_path"
    mock_args.context = "false"
    mock_args.token_engine_code=None
    mock_args.token_license_analyzer = None
    mock_args.use_license_analyzer = "false"
    mock_args.docker_address = "unix:///var/run/docker.sock"
    # Mock the parse_args method
    mock_parse_args.return_value = mock_args

    # Call the function
    result = get_inputs_from_cli(None)

    # Assert that the function returns the expected result
    assert result == {
        "platform_devops": "azure",
        "remote_config_repo": "https://github.com/example/repo",
        "remote_config_branch": "",
        "remote_config_source": "azure",
        "tool": None,
        "module": "engine_iac",
        "folder_path": "/path/to/folder",
        "terraform_repo_root": "/path/to/terraform/repo/root",
        "platform": "k8s,docker",
        "use_secrets_manager": "true",
        "use_vulnerability_management": "false",
        "send_metrics": "true",
        "token_cmdb": "abc123",
        "token_vulnerability_management": None,
        "token_engine_container": None,
        "token_engine_dependencies": None,
        "token_external_checks": None,
        "xray_mode": "scan",
        "image_to_scan": "image",
        "dast_file_path": "dast_file_path",
        "context": "false",
        "token_engine_code": None,
        "token_license_analyzer": None,
        "use_license_analyzer": "false",
        "docker_address": "unix:///var/run/docker.sock",
    }


def test_parse_choices():
    # Set up mock arguments
    result = parse_separated_list(
        "docker,k8s", {"all", "docker", "k8s", "cloudformation"}
    )
    assert result == ["docker", "k8s"]


def test_parse_separated_list_invalid_value():
    """Covers line 52: raise argparse.ArgumentTypeError for invalid values."""
    with pytest.raises(argparse.ArgumentTypeError):
        parse_separated_list("invalid", {"all", "docker", "k8s"})


def test_parse_choices_closure():
    """Covers line 61: the parse_with_choices inner function body."""
    fn = parse_choices({"all", "docker", "k8s"})
    result = fn("docker,k8s")
    assert result == ["docker", "k8s"]


@mock.patch("argparse.ArgumentParser.parse_args")
def test_get_inputs_from_cli_tool_not_allowed_for_module(mock_parse_args):
    """Covers lines 269-270: allowed_tools is None (e.g. engine_risk with a tool)."""
    mock_args = mock.MagicMock()
    mock_args.module = "engine_risk"
    mock_args.tool = "checkov"
    mock_parse_args.return_value = mock_args
    with pytest.raises(SystemExit):
        get_inputs_from_cli(None)


@mock.patch("argparse.ArgumentParser.parse_args")
def test_get_inputs_from_cli_tool_not_in_allowed_list(mock_parse_args):
    """Covers lines 271-273: tool not in allowed list for module (e.g. engine_iac + nuclei)."""
    mock_args = mock.MagicMock()
    mock_args.module = "engine_iac"
    mock_args.tool = "nuclei"
    mock_parse_args.return_value = mock_args
    with pytest.raises(SystemExit):
        get_inputs_from_cli(None)


@mock.patch(
    "devsecops_engine_tools.engine_core.src.applications.runner_engine_core.get_inputs_from_cli"
)
@mock.patch(
    "devsecops_engine_tools.engine_core.src.applications.runner_engine_core.DependencyTrack"
)
@mock.patch(
    "devsecops_engine_tools.engine_core.src.applications.runner_engine_core.ContextExtractionManager"
)
@mock.patch(
    "devsecops_engine_tools.engine_core.src.applications.runner_engine_core.RiskScore"
)
@mock.patch(
    "devsecops_engine_tools.engine_core.src.applications.runner_engine_core.CdxGen"
)
@mock.patch(
    "devsecops_engine_tools.engine_core.src.applications.runner_engine_core.Syft"
)
@mock.patch(
    "devsecops_engine_tools.engine_core.src.applications.runner_engine_core.PrinterPrettyTable"
)
@mock.patch(
    "devsecops_engine_tools.engine_core.src.applications.runner_engine_core.S3Manager"
)
@mock.patch(
    "devsecops_engine_tools.engine_core.src.applications.runner_engine_core.RuntimeLocal"
)
@mock.patch(
    "devsecops_engine_tools.engine_core.src.applications.runner_engine_core.GithubActions"
)
@mock.patch(
    "devsecops_engine_tools.engine_core.src.applications.runner_engine_core.AzureDevops"
)
@mock.patch(
    "devsecops_engine_tools.engine_core.src.applications.runner_engine_core.SecretsManager"
)
@mock.patch(
    "devsecops_engine_tools.engine_core.src.applications.runner_engine_core.DefectDojoPlatform"
)
@mock.patch(
    "devsecops_engine_tools.engine_core.src.applications.runner_engine_core.init_engine_core"
)
def test_application_core_exception_block(
    mock_init_engine_core,
    mock_defect_dojo,
    mock_secrets_manager,
    mock_azure_devops,
    mock_github_actions,
    mock_runtime_local,
    mock_s3_manager,
    mock_printer,
    mock_syft,
    mock_cdxgen,
    mock_risk_score,
    mock_ctx_extraction,
    mock_dependency_track,
    mock_get_inputs_from_cli,
):
    """Covers lines 321-333: the except block in application_core."""
    mock_args = {
        "platform_devops": "azure",
        "remote_config_source": "azure",
        "remote_config_repo": "repo",
        "remote_config_branch": "",
        "module": "engine_iac",
        "tool": None,
        "folder_path": None,
        "terraform_repo_root": None,
        "platform": "all",
        "use_secrets_manager": "false",
        "use_vulnerability_management": "false",
        "send_metrics": "false",
        "token_cmdb": None,
        "token_vulnerability_management": None,
        "token_engine_container": None,
        "token_engine_dependencies": None,
        "token_external_checks": None,
        "token_engine_code": None,
        "token_license_analyzer": None,
        "xray_mode": "scan",
        "image_to_scan": None,
        "dast_file_path": None,
        "context": "false",
        "docker_address": None,
    }
    mock_get_inputs_from_cli.return_value = mock_args
    mock_init_engine_core.side_effect = Exception("simulated error")

    application_core()

    mock_azure_devops.return_value.message.assert_called_once()
    mock_azure_devops.return_value.result_pipeline.assert_called_once_with("failed")


def test_main_block():
    """Covers line 357: application_core() call under if __name__ == '__main__'."""
    with mock.patch("sys.argv", ["runner_engine_core.py"]):
        with pytest.raises(SystemExit):
            runpy.run_module(
                "devsecops_engine_tools.engine_core.src.applications.runner_engine_core",
                run_name="__main__",
                alter_sys=True,
            )