import unittest
from unittest import mock
from devsecops_engine_tools.engine_sast.engine_iac.src.applications.runner_iac_scan import (
    runner_engine_iac,
)
from devsecops_engine_tools.engine_core.src.domain.model.input_core import InputCore
from devsecops_engine_tools.engine_core.src.domain.model.threshold import Threshold


@mock.patch(
    "devsecops_engine_tools.engine_sast.engine_iac.src.applications.runner_iac_scan.init_engine_sast_rm"
)
def test_runner_engine_iac(mock_entry_point_tool):
    # Mock the output

    input_core = InputCore(
        totalized_exclusions=[],
        threshold_defined=Threshold,
        path_file_results="test/file",
        custom_message_break_build="message",
        scope_pipeline="pipeline",
        stage_pipeline="Release",
    )

    mock_entry_point_tool.return_value = [] , input_core

    # Define the input arguments
    dict_args = {}
    tool = "CHECKOV"
    secret_tool = "secret"
    devops_platform_gateway = None

    # Call the function
    [] , input_output = runner_engine_iac(dict_args, tool, secret_tool, devops_platform_gateway, "qa")

    # Assert the expected behavior
    assert input_output == input_core

@mock.patch('devsecops_engine_tools.engine_sast.engine_iac.src.applications.runner_iac_scan.init_engine_sast_rm')
def test_runner_engine_iac_exception(mock_entry_point_tool):
        # Arrange
        dict_args = {'arg1': 'value1', 'arg2': 'value2'}
        tool = 'CHECKOV'
        secret_tool = 'my_secret'
        devops_platform_gateway = None

        # Mock the necessary methods or properties to simulate an exception
        mock_entry_point_tool.side_effect = Exception("Simulated error")

        # Act and Assert
        with unittest.TestCase().assertRaises(Exception) as context:
            runner_engine_iac(dict_args, tool, secret_tool, devops_platform_gateway, "dev")

        # Optionally, you can check the exception message or other details
        assert str(context.exception) == "Error engine_iac : Simulated error"

@mock.patch(
    "devsecops_engine_tools.engine_sast.engine_iac.src.applications.runner_iac_scan.init_engine_sast_rm"
)
def test_runner_engine_iac_kubescape(mock_entry_point_tool):
    # Mock the output

    input_core = InputCore(
        totalized_exclusions=[],
        threshold_defined=Threshold,
        path_file_results="test/file",
        custom_message_break_build="message",
        scope_pipeline="pipeline",
        stage_pipeline="Release",
    )

    mock_entry_point_tool.return_value = [] , input_core

    # Define the input arguments
    dict_args = {}
    tool = "KUBESCAPE"
    secret_tool = "secret"
    devops_platform_gateway = None

    # Call the function
    [] , input_output = runner_engine_iac(dict_args, tool, secret_tool, devops_platform_gateway, "qa")

    # Assert the expected behavior
    assert input_output == input_core

@mock.patch(
    "devsecops_engine_tools.engine_sast.engine_iac.src.applications.runner_iac_scan.init_engine_sast_rm"
)
def test_runner_engine_iac_kics(mock_entry_point_tool):
    # Mock the output

    input_core = InputCore(
        totalized_exclusions=[],
        threshold_defined=Threshold,
        path_file_results="test/file",
        custom_message_break_build="message",
        scope_pipeline="pipeline",
        stage_pipeline="Release",
    )

    mock_entry_point_tool.return_value = [] , input_core

    # Define the input arguments
    dict_args = {}
    tool = "KICS"
    secret_tool = "secret"
    devops_platform_gateway = None

    # Call the function
    [] , input_output = runner_engine_iac(dict_args, tool, secret_tool, devops_platform_gateway, "qa")

    # Assert the expected behavior
    assert input_output == input_core
