from devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.usecases.handle_remote_config_patterns import (
    HandleRemoteConfigPatterns,
)

import pytest
from unittest.mock import mock_open, patch, Mock


def test_init():
    with patch(
        "devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway.DevopsPlatformGateway"
    ) as mock_tool_remote:
        dict_args = {"key1": "value1", "key2": "value2"}
        handle_remote_config_patterns_instance = HandleRemoteConfigPatterns(
            mock_tool_remote, dict_args
        )

        assert handle_remote_config_patterns_instance.tool_remote == mock_tool_remote
        assert handle_remote_config_patterns_instance.dict_args == dict_args


def test_get_remote_config():
    with patch(
        "devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway.DevopsPlatformGateway"
    ) as mock_tool_remote:
        mock_tool_remote.get_remote_config.return_value = {
            "remote_config_key": "remote_config_value"
        }
        dict_args = {
            "dict_args_key": "dict_args_value",
            "remote_config_repo": "remote_config_repo_value",
        }
        file_path = "/path/to/file.txt"
        handle_remote_config_patterns_instance = HandleRemoteConfigPatterns(
            mock_tool_remote, dict_args
        )
        result = handle_remote_config_patterns_instance.get_remote_config(file_path)

        mock_tool_remote.get_remote_config.assert_called_once_with(
            dict_args["remote_config_repo"], file_path
        )
        assert result == {"remote_config_key": "remote_config_value"}


def test_get_variable():
    with patch(
        "devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway.DevopsPlatformGateway"
    ) as mock_tool_remote:
        mock_tool_remote.get_remote_config.return_value = {
            "remote_config_key": "remote_config_value"
        }
        dict_args = {"dict_args_key": "dict_args_value"}
        variable = "test_variable"
        handle_remote_config_patterns_instance = HandleRemoteConfigPatterns(
            mock_tool_remote, dict_args
        )
        result = handle_remote_config_patterns_instance.get_variable(variable)

        mock_tool_remote.get_variable.assert_called_once_with(variable)


def test_handle_excluded_files():
    with patch(
        "devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway.DevopsPlatformGateway"
    ) as mock_tool_remote:
        mock_tool_remote.get_remote_config.return_value = {
            "remote_config_key": "remote_config_value"
        }
        dict_args = {"dict_args_key": "dict_args_value"}
        pipeline_name = "pipeline1"
        pattern = ".js|.py|.txt"
        exclusions = {"pipeline1": {"SKIP_FILES": {"files": [".py", ".txt"]}}}
        expected_result = ".js"
        handle_remote_config_patterns_instance = HandleRemoteConfigPatterns(
            mock_tool_remote, dict_args
        )
        result = handle_remote_config_patterns_instance.handle_excluded_files(
            pattern, pipeline_name, exclusions
        )

        assert result == expected_result


def test_process_handle_excluded_files():
    with patch(
        "devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway.DevopsPlatformGateway"
    ) as mock_tool_remote:
        mock_tool_remote.get_remote_config.return_value = {
            "remote_config_key": "remote_config_value",
            "REGEX_EXPRESSION_EXTENSIONS": "regex",
        }
        dict_args = {
            "dict_args_key": "dict_args_value",
            "remote_config_repo": "remote_config_repo_value",
        }
        handle_remote_config_patterns_instance = HandleRemoteConfigPatterns(
            mock_tool_remote, dict_args
        )
        handle_remote_config_patterns_instance.process_handle_excluded_files()

        mock_tool_remote.get_remote_config.assert_any_call
        mock_tool_remote.get_variable.assert_any_call


def test_handle_analysis_pattern_matched():
    with patch(
        "devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway.DevopsPlatformGateway"
    ) as mock_tool_remote:
        mock_tool_remote.get_remote_config.return_value = {
            "remote_config_key": "remote_config_value",
        }
        dict_args = {
            "dict_args_key": "dict_args_value",
            "remote_config_repo": "remote_config_repo_value",
        }
        ignore = "(.*_test|Template_.*)"
        pipeline_name = "pipeline_test"
        handle_remote_config_patterns_instance = HandleRemoteConfigPatterns(
            mock_tool_remote, dict_args
        )
        result = handle_remote_config_patterns_instance.handle_analysis_pattern(
            ignore, pipeline_name
        )

        assert result == False


def test_handle_analysis_pattern_not_matched():
    with patch(
        "devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway.DevopsPlatformGateway"
    ) as mock_tool_remote:
        mock_tool_remote.get_remote_config.return_value = {
            "remote_config_key": "remote_config_value",
        }
        dict_args = {
            "dict_args_key": "dict_args_value",
            "remote_config_repo": "remote_config_repo_value",
        }
        ignore = "(.*_test|Template_.*)"
        pipeline_name = "pipeline"
        handle_remote_config_patterns_instance = HandleRemoteConfigPatterns(
            mock_tool_remote, dict_args
        )
        result = handle_remote_config_patterns_instance.handle_analysis_pattern(
            ignore, pipeline_name
        )

        assert result == True


def test_process_handle_analysis_pattern():
    with patch(
        "devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway.DevopsPlatformGateway"
    ) as mock_tool_remote:
        mock_tool_remote.get_remote_config.return_value = {
            "remote_config_key": "remote_config_value",
            "IGNORE_ANALYSIS_PATTERN": "(.*_test|Template_.*)",
        }
        mock_tool_remote.get_variable.return_value = "pipeline_name"
        dict_args = {
            "dict_args_key": "dict_args_value",
            "remote_config_repo": "remote_config_repo_value",
        }
        handle_remote_config_patterns_instance = HandleRemoteConfigPatterns(
            mock_tool_remote, dict_args
        )
        handle_remote_config_patterns_instance.process_handle_analysis_pattern()

        mock_tool_remote.get_remote_config.assert_any_call
        mock_tool_remote.get_variable.assert_any_call


def test_handle_bypass_expression_matched():
    with patch(
        "devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway.DevopsPlatformGateway"
    ) as mock_tool_remote:
        mock_tool_remote.get_remote_config.return_value = {
            "remote_config_key": "remote_config_value",
        }
        dict_args = {
            "dict_args_key": "dict_args_value",
            "remote_config_repo": "remote_config_repo_value",
        }
        bypass_limits = "(pipeline1|pipeline2)"
        pipeline_name = "pipeline1"
        handle_remote_config_patterns_instance = HandleRemoteConfigPatterns(
            mock_tool_remote, dict_args
        )
        result = handle_remote_config_patterns_instance.handle_bypass_expression(
            bypass_limits, pipeline_name
        )

        assert result == True


def test_handle_bypass_expression_not_matched():
    with patch(
        "devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway.DevopsPlatformGateway"
    ) as mock_tool_remote:
        mock_tool_remote.get_remote_config.return_value = {
            "remote_config_key": "remote_config_value",
        }
        dict_args = {
            "dict_args_key": "dict_args_value",
            "remote_config_repo": "remote_config_repo_value",
        }
        bypass_limits = "(pipeline1|pipeline2)"
        pipeline_name = "pipeline"
        handle_remote_config_patterns_instance = HandleRemoteConfigPatterns(
            mock_tool_remote, dict_args
        )
        result = handle_remote_config_patterns_instance.handle_bypass_expression(
            bypass_limits, pipeline_name
        )

        assert result == False


def test_process_handle_bypass_expression():
    with patch(
        "devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway.DevopsPlatformGateway"
    ) as mock_tool_remote:
        mock_tool_remote.get_remote_config.return_value = {
            "remote_config_key": "remote_config_value",
            "BYPASS_ARCHIVE_LIMITS": "(pipeline1|pipeline2)",
        }
        mock_tool_remote.get_variable.return_value = "pipeline_name"
        dict_args = {
            "dict_args_key": "dict_args_value",
            "remote_config_repo": "remote_config_repo_value",
        }
        handle_remote_config_patterns_instance = HandleRemoteConfigPatterns(
            mock_tool_remote, dict_args
        )
        handle_remote_config_patterns_instance.process_handle_bypass_expression()

        mock_tool_remote.get_remote_config.assert_any_call
        mock_tool_remote.get_variable.assert_any_call


def test_handle_skip_tool_skip():
    with patch(
        "devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway.DevopsPlatformGateway"
    ) as mock_tool_remote:
        mock_tool_remote.get_remote_config.return_value = {
            "remote_config_key": "remote_config_value",
        }
        dict_args = {
            "dict_args_key": "dict_args_value",
            "remote_config_repo": "remote_config_repo_value",
        }
        exclusions = {"pipeline1": {"SKIP_TOOL": {"hu": ""}}}
        enabled = "true"
        pipeline_name = "pipeline1"
        handle_remote_config_patterns_instance = HandleRemoteConfigPatterns(
            mock_tool_remote, dict_args
        )
        result = handle_remote_config_patterns_instance.handle_skip_tool(
            exclusions, pipeline_name, enabled
        )

        assert result == True


def test_handle_skip_tool_not_skip():
    with patch(
        "devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway.DevopsPlatformGateway"
    ) as mock_tool_remote:
        mock_tool_remote.get_remote_config.return_value = {
            "remote_config_key": "remote_config_value",
        }
        dict_args = {
            "dict_args_key": "dict_args_value",
            "remote_config_repo": "remote_config_repo_value",
        }
        exclusions = {"pipeline1": {"SKIP_TOOL": {"hu": ""}}}
        enabled = "true"
        pipeline_name = "pipeline"
        handle_remote_config_patterns_instance = HandleRemoteConfigPatterns(
            mock_tool_remote, dict_args
        )
        result = handle_remote_config_patterns_instance.handle_skip_tool(
            exclusions, pipeline_name, enabled
        )

        assert result == False


def test_process_handle_skip_tool():
    with patch(
        "devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway.DevopsPlatformGateway"
    ) as mock_tool_remote:
        mock_tool_remote.get_remote_config.return_value = {
            "remote_config_key": "remote_config_value",
            "ENGINE_DEPENDENCIES": {"ENABLED": "true"},
        }
        mock_tool_remote.get_variable.return_value = "pipeline_name"
        dict_args = {
            "dict_args_key": "dict_args_value",
            "remote_config_repo": "remote_config_repo_value",
        }
        handle_remote_config_patterns_instance = HandleRemoteConfigPatterns(
            mock_tool_remote, dict_args
        )
        handle_remote_config_patterns_instance.process_handle_skip_tool()

        mock_tool_remote.get_remote_config.assert_any_call
        mock_tool_remote.get_variable.assert_any_call


def test_handle_working_directory_agentdir():
    with patch(
        "devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway.DevopsPlatformGateway"
    ) as mock_tool_remote, patch("os.walk") as mock_walk:
        mock_tool_remote.get_remote_config.return_value = {
            "remote_config_key": "remote_config_value",
            "ENGINE_DEPENDENCIES": {"ENABLED": "true"},
        }
        mock_tool_remote.get_variable.return_value = "pipeline_name"
        dict_args = {
            "dict_args_key": "dict_args_value",
            "remote_config_repo": "remote_config_repo_value",
        }
        work_dir_different_flag = "test_dir"
        agent_directory = "/path/to/agent"
        mock_walk.return_value = [
            (agent_directory, ["dir1", "dir2"], ["file1.txt", "file2.json"]),
            (agent_directory + "/dir1", [], ["file3.ear"]),
            (agent_directory + "/dir2", ["test_dir"], ["file4.war"]),
        ]
        handle_remote_config_patterns_instance = HandleRemoteConfigPatterns(
            mock_tool_remote, dict_args
        )
        result = handle_remote_config_patterns_instance.handle_working_directory(
            work_dir_different_flag, agent_directory
        )

        assert result == agent_directory


def test_handle_working_directory_workingdir():
    with patch(
        "devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway.DevopsPlatformGateway"
    ) as mock_tool_remote, patch("os.walk") as mock_walk, patch(
        "os.getcwd"
    ) as mock_getcwd:
        mock_tool_remote.get_remote_config.return_value = {
            "remote_config_key": "remote_config_value",
            "ENGINE_DEPENDENCIES": {"ENABLED": "true"},
        }
        mock_tool_remote.get_variable.return_value = "pipeline_name"
        dict_args = {
            "dict_args_key": "dict_args_value",
            "remote_config_repo": "remote_config_repo_value",
        }
        mock_getcwd.return_value = "/path/to/woaking/dir"
        work_dir_different_flag = "test_dir"
        agent_directory = None
        mock_walk.return_value = [
            ("/agent_directory", ["dir1", "dir2"], ["file1.txt", "file2.json"]),
            ("/agent_directory" + "/dir1", [], ["file3.ear"]),
            ("/agent_directory" + "/dir2", ["test_dir"], ["file4.war"]),
        ]
        handle_remote_config_patterns_instance = HandleRemoteConfigPatterns(
            mock_tool_remote, dict_args
        )
        result = handle_remote_config_patterns_instance.handle_working_directory(
            work_dir_different_flag, agent_directory
        )

        assert result == "/path/to/woaking/dir"


def test_process_handle_working_directory():
    with patch(
        "devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway.DevopsPlatformGateway"
    ) as mock_tool_remote:
        mock_tool_remote.get_remote_config.return_value = {
            "remote_config_key": "remote_config_value",
            "WORK_DIR_DIFFERENT_FLAG": "test_dir",
        }
        mock_tool_remote.get_variable.return_value = "agent_directory"
        dict_args = {
            "dict_args_key": "dict_args_value",
            "remote_config_repo": "remote_config_repo_value",
        }
        handle_remote_config_patterns_instance = HandleRemoteConfigPatterns(
            mock_tool_remote, dict_args
        )
        handle_remote_config_patterns_instance.process_handle_working_directory()

        mock_tool_remote.get_remote_config.assert_any_call
        mock_tool_remote.get_variable.assert_any_call
