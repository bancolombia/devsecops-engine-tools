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

    # Call the function
    [] , input_output = runner_engine_iac(dict_args, tool, secret_tool)

    # Assert the expected behavior
    assert input_output == input_core
