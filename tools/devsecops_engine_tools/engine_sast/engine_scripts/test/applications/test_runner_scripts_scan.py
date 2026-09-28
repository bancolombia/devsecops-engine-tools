import unittest
from unittest import mock
from devsecops_engine_tools.engine_sast.engine_scripts.src.applications.runner_scripts_scan import (
    runner_engine_scripts,
)
from devsecops_engine_tools.engine_core.src.domain.model.input_core import InputCore
from devsecops_engine_tools.engine_core.src.domain.model.threshold import Threshold


@mock.patch(
    "devsecops_engine_tools.engine_sast.engine_scripts.src.applications.runner_scripts_scan.init_engine_sast_rm"
)
def test_runner_engine_scripts(mock_entry_point_tool):
    input_core = InputCore(
        totalized_exclusions=[],
        threshold_defined=Threshold,
        path_file_results="test/file",
        custom_message_break_build="message",
        scope_pipeline="pipeline",
        scope_service="service",
        stage_pipeline="Release",
    )

    mock_entry_point_tool.return_value = [], input_core

    dict_args = {}
    tool = "SCRIPT"
    secret_tool = "secret"
    devops_platform_gateway = None
    remote_config_source_gateway = None

    findings_list, input_output, tool_gateway = runner_engine_scripts(
        dict_args, tool, secret_tool, devops_platform_gateway, remote_config_source_gateway, "qa"
    )

    assert findings_list == []
    assert input_output == input_core
    assert tool_gateway is not None


@mock.patch(
    "devsecops_engine_tools.engine_sast.engine_scripts.src.applications.runner_scripts_scan.init_engine_sast_rm"
)
def test_runner_engine_scripts_unknown_tool_returns_none_gateway(mock_entry_point_tool):
    input_core = InputCore(
        totalized_exclusions=[],
        threshold_defined=Threshold,
        path_file_results=None,
        custom_message_break_build="message",
        scope_pipeline="pipeline",
        scope_service="service",
        stage_pipeline="Release",
    )
    mock_entry_point_tool.return_value = [], input_core

    findings_list, input_output, tool_gateway = runner_engine_scripts(
        {}, "UNKNOWN_TOOL", "secret", None, None, "qa"
    )

    assert tool_gateway is None


@mock.patch(
    "devsecops_engine_tools.engine_sast.engine_scripts.src.applications.runner_scripts_scan.init_engine_sast_rm"
)
def test_runner_engine_scripts_exception(mock_entry_point_tool):
    dict_args = {"arg1": "value1"}
    tool = "SCRIPT"
    secret_tool = "my_secret"
    devops_platform_gateway = None
    remote_config_source_gateway = None

    mock_entry_point_tool.side_effect = Exception("Simulated error")

    with unittest.TestCase().assertRaises(RuntimeError) as context:
        runner_engine_scripts(
            dict_args, tool, secret_tool, devops_platform_gateway, remote_config_source_gateway, "dev"
        )

    assert str(context.exception) == "Error engine_scripts : Simulated error"
