import unittest
from unittest import mock
from devsecops_engine_tools.engine_sast.engine_secret.src.applications.runner_secret_scan import (
    runner_secret_scan,
)
from devsecops_engine_tools.engine_core.src.domain.model.input_core import InputCore
from devsecops_engine_tools.engine_core.src.domain.model.threshold import Threshold


@mock.patch(
    "devsecops_engine_tools.engine_sast.engine_secret.src.applications.runner_secret_scan.engine_secret_scan"
)
def test_runner_secret_scan(mock_entry_point_tool):
    # Mock the output
    input_core = InputCore(
        totalized_exclusions=[],
        threshold_defined=Threshold,
        path_file_results="test/file",
        custom_message_break_build="message",
        scope_pipeline="pipeline",
        stage_pipeline="pipeline",
    )

    mock_entry_point_tool.return_value = [] , input_core

    # Define the input arguments
    dict_args = {}
    tool = "TRUFFLEHOG"

    # Call the function
    [] , input_output = runner_secret_scan(dict_args, tool)

    # Assert the expected behavior
    assert input_output == input_core

@mock.patch('devsecops_engine_tools.engine_sast.engine_secret.src.applications.runner_secret_scan.engine_secret_scan')
def test_runner_secret_scan_exception(mock_entry_point_tool):
        # Arrange
        dict_args = {'arg1': 'value1', 'arg2': 'value2'}
        tool = 'CHECKOV'
        
        # Mock the necessary methods or properties to simulate an exception
        mock_entry_point_tool.side_effect = Exception("Simulated error")

        # Act and Assert
        with unittest.TestCase().assertRaises(Exception) as context:
            runner_secret_scan(dict_args, tool)

        # Optionally, you can check the exception message or other details
        assert str(context.exception) == "Error engine_iac : Simulated error"
