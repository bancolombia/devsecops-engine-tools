from devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.usecases.set_input_core import (
    SetInputCore,
)

import pytest
from unittest.mock import mock_open, patch, Mock


def test_init():
    remote_config = {"key": "value"}
    exclusions = {"exclusion": "value"}
    pipeline_name = "pipeline"
    tool = "XRAY"

    set_input_core_instance = SetInputCore(
        remote_config, exclusions, pipeline_name, tool
    )

    assert set_input_core_instance.remote_config == remote_config
    assert set_input_core_instance.exclusions == exclusions
    assert set_input_core_instance.pipeline_name == pipeline_name
    assert set_input_core_instance.tool == tool


# def test_get_remote_config():
#     with patch(
#         "devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway.DevopsPlatformGateway"
#     ) as mock_tool_remote:
#         mock_tool_remote.get_remote_config.return_value = {
#             "remote_config_key": "remote_config_value"
#         }
#         dict_args = {
#             "dict_args_key": "dict_args_value",
#             "remote_config_repo": "remote_config_repo_value",
#         }
#         file_path = "/path/to/file.txt"
#         tool = "XRAY"
#         set_input_core_instance = SetInputCore(mock_tool_remote, dict_args, tool)
#         result = set_input_core_instance.get_remote_config(file_path)

#         mock_tool_remote.get_remote_config.assert_called_once_with(
#             dict_args["remote_config_repo"], file_path
#         )
#         assert result == {"remote_config_key": "remote_config_value"}


# def test_get_variable():
#     with patch(
#         "devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway.DevopsPlatformGateway"
#     ) as mock_tool_remote:
#         mock_tool_remote.get_remote_config.return_value = {
#             "remote_config_key": "remote_config_value"
#         }
#         dict_args = {"dict_args_key": "dict_args_value"}
#         variable = "test_variable"
#         tool = "XRAY"
#         set_input_core_instance = SetInputCore(mock_tool_remote, dict_args, tool)
#         result = set_input_core_instance.get_variable(variable)

#         mock_tool_remote.get_variable.assert_called_once_with(variable)


def test_get_exclusions():
    exclusions = {
        "All": {
            "XRAY": [
                {
                    "id": "1",
                    "where": "module1",
                    "cve_id": "CVE-2021-1234",
                    "create_date": "2021-01-01",
                    "expired_date": "2021-12-31",
                    "severity": "high",
                    "hu": "user1",
                },
                {
                    "id": "2",
                    "where": "module2",
                    "cve_id": "CVE-2021-5678",
                    "create_date": "2021-02-01",
                    "expired_date": "2021-12-31",
                    "severity": "medium",
                    "hu": "user2",
                },
            ]
        },
        "Pipeline1": {
            "XRAY": [
                {
                    "id": "3",
                    "where": "module3",
                    "cve_id": "CVE-2021-9012",
                    "create_date": "2021-03-01",
                    "expired_date": "2021-12-31",
                    "severity": "low",
                    "hu": "user3",
                },
                {
                    "id": "4",
                    "where": "module4",
                    "cve_id": "CVE-2021-3456",
                    "create_date": "2021-04-01",
                    "expired_date": "2021-12-31",
                    "severity": "high",
                    "hu": "user4",
                },
            ]
        },
    }
    pipeline_name = "Pipeline1"
    tool = "XRAY"
    remote_config = {"key": "value"}

    set_input_core_instance = SetInputCore(
        remote_config, exclusions, pipeline_name, tool
    )
    result = set_input_core_instance.get_exclusions(exclusions, pipeline_name, tool)

    assert len(result) == 4


def test_set_input_core():
    with patch(
        "devsecops_engine_tools.engine_core.src.domain.model.input_core.InputCore"
    ) as mock_inputcore, patch(
        "devsecops_engine_tools.engine_core.src.domain.model.threshold.Threshold"
    ) as mock_threshold, patch(
        "devsecops_engine_tools.engine_core.src.domain.model.exclusions.Exclusions"
    ) as mock_exclusions:
        remote_config = {
            "THRESHOLD": {
                "VULNERABILITY": {
                    "Critical": 999,
                    "High": 999,
                    "Medium": 999,
                    "Low": 999,
                },
                "COMPLIANCE": {"Critical": 1},
            },
            "MESSAGE_INFO_SCA": "Test",
        }
        exclusions = {"exclusion": "value"}
        dependencies_scanned = "tests_file"
        tool = "XRAY"
        pipeline_name = "Pipeline1"

        set_input_core_instance = SetInputCore(
            remote_config, exclusions, pipeline_name, tool
        )
        set_input_core_instance.set_input_core(dependencies_scanned)

        mock_inputcore.assert_any_call
