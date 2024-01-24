import unittest
from unittest import mock
from devsecops_engine_tools.engine_core.src.applications.runner_engine_core import (
    application_core,
)


@mock.patch(
    "devsecops_engine_tools.engine_core.src.applications.runner_engine_core.init_engine_core"
)
def test_application_core(mock_entry_point_tool):
    # Mock the dependencies
    init_output = mock_entry_point_tool.return_value = "ok"

    # Call the function
    application_core()

    # Assert that the dependencies are initialized correctly
    assert init_output == "ok"

@mock.patch(
    "devsecops_engine_tools.engine_core.src.applications.runner_engine_core.init_engine_core"
)
@mock.patch("devsecops_engine_tools.engine_core.src.applications.runner_engine_core.MyLogger.get_logger")
@mock.patch("builtins.print")
def test_application_core_exception(mock_print, mock_logger ,mock_entry_point_tool):
    # Mock the necessary methods or properties to simulate an exception
    mock_entry_point_tool.side_effect = Exception("Simulated error")

    # Act and Assert
    application_core()

    # Optionally, you can check the exception message or other details
    mock_print.assert_called()
