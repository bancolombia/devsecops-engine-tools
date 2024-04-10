from unittest.mock import MagicMock
from unittest import mock
from devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.entry_points.entry_point_tool import engine_secret_scan
from devsecops_engine_tools.engine_core.src.domain.model.input_core import InputCore
from devsecops_engine_tools.engine_core.src.domain.model.threshold import Threshold


@mock.patch('devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.entry_points.entry_point_tool.SecretScan')
def test_engine_secret_scan(mock_secret_scan):
    # Mock the output

    input_core = InputCore(
        totalized_exclusions=[],
        threshold_defined=Threshold,
        path_file_results="test/file",
        custom_message_break_build="message",
        scope_pipeline="pipeline",
        stage_pipeline="Release",
    )

    mock_secret_scan.return_value.process.return_value = [] , input_core

    # Define the input arguments
    devops_platform_gateway = MagicMock()
    tool_gateway = MagicMock()
    tool_deserializator = MagicMock()
    git_gateway = MagicMock()
    dict_args = {}
    tool = "TRUFFLEHOG"

    # Call the function
    [] , input_output = engine_secret_scan(devops_platform_gateway, tool_gateway, dict_args, tool, tool_deserializator, git_gateway)

    # Assert the expected behavior
    assert input_output == input_core