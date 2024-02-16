from devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.usecases.dependencies_sca_scan import (
    DependenciesScan,
)

import pytest
from unittest.mock import mock_open, patch, Mock


def test_get_remote_config():
    with patch(
        "devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway.DevopsPlatformGateway"
    ) as mock_tool_remote, patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.model.gateways.tool_gateway.ToolGateway"
    ) as mock_tool_gateway, patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.model.gateways.deserializator_gateway"
    ) as mock_deserializator_gateway:
        mock_tool_remote.get_remote_config.return_value = {
            "remote_config_key": "remote_config_value"
        }
        dict_args = {
            "dict_args_key": "dict_args_value",
            "remote_config_repo": "remote_config_repo_value",
        }
        file_path = "/path/to/file.txt"
        working_dir = "/path/to/working/dir"
        skip_flag = True
        scan_flag = True
        bypass_limits_flag = True
        pattern = "pattern"
        token = "token"
        dependencies_scan_instance = DependenciesScan(
            mock_tool_gateway,
            mock_tool_remote,
            mock_deserializator_gateway,
            dict_args,
            working_dir,
            skip_flag,
            scan_flag,
            bypass_limits_flag,
            pattern,
            token,
        )
        result = dependencies_scan_instance.get_remote_config(file_path)

        mock_tool_remote.get_remote_config.assert_called_once_with(
            dict_args["remote_config_repo"], file_path
        )
        assert result == {"remote_config_key": "remote_config_value"}


def test_process():
    with patch(
        "devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway.DevopsPlatformGateway"
    ) as mock_tool_remote, patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.model.gateways.tool_gateway.ToolGateway"
    ) as mock_tool_gateway, patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.model.gateways.deserializator_gateway"
    ) as mock_deserializator_gateway:
        mock_tool_remote.get_remote_config.return_value = {
            "remote_config_key": "remote_config_value"
        }
        dict_args = {
            "dict_args_key": "dict_args_value",
            "remote_config_repo": "remote_config_repo_value",
        }
        file_path = "SCA/DEPENDENCIES/configTools.json"
        working_dir = "/path/to/working/dir"
        skip_flag = True
        scan_flag = True
        bypass_limits_flag = True
        pattern = "pattern"
        token = "token"
        dependencies_scan_instance = DependenciesScan(
            mock_tool_gateway,
            mock_tool_remote,
            mock_deserializator_gateway,
            dict_args,
            working_dir,
            skip_flag,
            scan_flag,
            bypass_limits_flag,
            pattern,
            token,
        )
        dependencies_scan_instance.process()

        mock_tool_remote.get_remote_config.assert_called_once_with(
            dict_args["remote_config_repo"], file_path
        )


def test_deserializator():
    with patch(
        "devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway.DevopsPlatformGateway"
    ) as mock_tool_remote, patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.model.gateways.tool_gateway.ToolGateway"
    ) as mock_tool_gateway, patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.model.gateways.deserializator_gateway"
    ) as mock_deserializator_gateway:
        mock_tool_remote.get_remote_config.return_value = {
            "remote_config_key": "remote_config_value"
        }
        dict_args = {
            "dict_args_key": "dict_args_value",
            "remote_config_repo": "remote_config_repo_value",
        }
        dependencies_scanned = "scanned.json"
        working_dir = "/path/to/working/dir"
        skip_flag = True
        scan_flag = True
        bypass_limits_flag = True
        pattern = "pattern"
        token = "token"
        dependencies_scan_instance = DependenciesScan(
            mock_tool_gateway,
            mock_tool_remote,
            mock_deserializator_gateway,
            dict_args,
            working_dir,
            skip_flag,
            scan_flag,
            bypass_limits_flag,
            pattern,
            token,
        )
        result = dependencies_scan_instance.deserializator(dependencies_scanned)

        mock_deserializator_gateway.get_list_findings.assert_called_once_with(
            dependencies_scanned
        )
