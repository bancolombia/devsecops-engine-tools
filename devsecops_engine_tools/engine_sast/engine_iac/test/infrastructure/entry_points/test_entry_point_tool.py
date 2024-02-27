from unittest.mock import MagicMock
from unittest import mock
from devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.entry_points.entry_point_tool import init_engine_sast_rm
from devsecops_engine_tools.engine_core.src.domain.model.input_core import InputCore
from devsecops_engine_tools.engine_core.src.domain.model.threshold import Threshold


@mock.patch('devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.entry_points.entry_point_tool.IacScan')
def test_init_engine_sast_rm(mock_iac_scan):
    # Mock the output

    input_core = InputCore(
        totalized_exclusions=[],
        threshold_defined=Threshold,
        path_file_results="test/file",
        custom_message_break_build="message",
        scope_pipeline="pipeline",
        stage_pipeline="Release",
    )

    mock_iac_scan.return_value.process.return_value = [] , input_core

    # Define the input arguments
    devops_platform_gateway = MagicMock()
    tool_gateway = MagicMock()
    dict_args = {}
    secret_tool = "secret"
    tool = "CHECKOV"

    # Call the function
    [] , input_output = init_engine_sast_rm(devops_platform_gateway, tool_gateway, dict_args, secret_tool, tool)

    # Assert the expected behavior
    assert input_output == input_core