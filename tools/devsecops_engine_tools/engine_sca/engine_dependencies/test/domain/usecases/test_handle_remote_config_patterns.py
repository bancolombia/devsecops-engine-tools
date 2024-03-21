from devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.usecases.handle_remote_config_patterns import (
    HandleRemoteConfigPatterns,
)

import pytest
from unittest.mock import mock_open, patch, Mock


def test_init():
    remote_config = {"remote_config_key": "remote_config_value"}
    exclusions = {"Exclusion": "Exclusion_value"}
    pipeline_name = "pipeline"
    agent_directory = "agent_directory"

    handle_remote_config_patterns_instance = HandleRemoteConfigPatterns(
        remote_config, exclusions, pipeline_name, agent_directory
    )

    assert handle_remote_config_patterns_instance.remote_config == remote_config
    assert handle_remote_config_patterns_instance.exclusions == exclusions
    assert handle_remote_config_patterns_instance.pipeline_name == pipeline_name
    assert handle_remote_config_patterns_instance.agent_directory == agent_directory


def test_handle_excluded_files():
    remote_config = {"remote_config_key": "remote_config_value"}
    pipeline_name = "pipeline1"
    pattern = ".js|.py|.txt"
    exclusions = {"pipeline1": {"SKIP_FILES": {"files": [".py", ".txt"]}}}
    agent_directory = "agent_directory"
    expected_result = ".js"

    handle_remote_config_patterns_instance = HandleRemoteConfigPatterns(
        remote_config, exclusions, pipeline_name, agent_directory
    )
    result = handle_remote_config_patterns_instance.handle_excluded_files(
        pattern, pipeline_name, exclusions
    )

    assert result == expected_result


def test_process_handle_excluded_files():
    with patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.usecases.handle_remote_config_patterns.HandleRemoteConfigPatterns.handle_excluded_files"
    ) as mock_handle_excluded_files:
        remote_config = {
            "remote_config_key": "remote_config_value",
            "REGEX_EXPRESSION_EXTENSIONS": "regex",
        }
        pipeline_name = "pipeline1"
        exclusions = {"pipeline1": {"SKIP_FILES": {"files": [".py", ".txt"]}}}
        agent_directory = "agent_directory"

        handle_remote_config_patterns_instance = HandleRemoteConfigPatterns(
            remote_config, exclusions, pipeline_name, agent_directory
        )
        handle_remote_config_patterns_instance.process_handle_excluded_files()

        mock_handle_excluded_files.assert_called_with(
            "regex", pipeline_name, exclusions
        )


def test_handle_analysis_pattern_matched():
    remote_config = {
        "remote_config_key": "remote_config_value",
    }
    ignore = "(.*_test|Template_.*)"
    pipeline_name = "pipeline_test"
    exclusions = {"pipeline1": {"SKIP_FILES": {"files": [".py", ".txt"]}}}
    agent_directory = "agent_directory"

    handle_remote_config_patterns_instance = HandleRemoteConfigPatterns(
        remote_config, exclusions, pipeline_name, agent_directory
    )
    result = handle_remote_config_patterns_instance.handle_analysis_pattern(
        ignore, pipeline_name
    )

    assert result == False


def test_handle_analysis_pattern_not_matched():
    remote_config = {
        "remote_config_key": "remote_config_value",
    }
    ignore = "(.*_test|Template_.*)"
    pipeline_name = "pipeline"
    exclusions = {"pipeline1": {"SKIP_FILES": {"files": [".py", ".txt"]}}}
    agent_directory = "agent_directory"

    handle_remote_config_patterns_instance = HandleRemoteConfigPatterns(
        remote_config, exclusions, pipeline_name, agent_directory
    )
    result = handle_remote_config_patterns_instance.handle_analysis_pattern(
        ignore, pipeline_name
    )

    assert result == True


def test_process_handle_analysis_pattern():
    with patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.usecases.handle_remote_config_patterns.HandleRemoteConfigPatterns.handle_analysis_pattern"
    ) as mock_handle_analysis_pattern:
        remote_config = {
            "remote_config_key": "remote_config_value",
            "IGNORE_ANALYSIS_PATTERN": "(.*_test|Template_.*)",
        }
        pipeline_name = "pipeline_name"
        exclusions = {"pipeline1": {"SKIP_FILES": {"files": [".py", ".txt"]}}}
        agent_directory = "agent_directory"

        handle_remote_config_patterns_instance = HandleRemoteConfigPatterns(
            remote_config, exclusions, pipeline_name, agent_directory
        )
        handle_remote_config_patterns_instance.process_handle_analysis_pattern()

        mock_handle_analysis_pattern.assert_called_with(
            "(.*_test|Template_.*)", pipeline_name
        )


def test_handle_bypass_expression_matched():
    remote_config = {
        "remote_config_key": "remote_config_value",
    }
    bypass_limits = "(pipeline1|pipeline2)"
    pipeline_name = "pipeline1"
    exclusions = {"pipeline1": {"SKIP_FILES": {"files": [".py", ".txt"]}}}
    agent_directory = "agent_directory"

    handle_remote_config_patterns_instance = HandleRemoteConfigPatterns(
        remote_config, exclusions, pipeline_name, agent_directory
    )
    result = handle_remote_config_patterns_instance.handle_bypass_expression(
        bypass_limits, pipeline_name
    )

    assert result == True


def test_handle_bypass_expression_not_matched():
    remote_config = {
        "remote_config_key": "remote_config_value",
    }
    bypass_limits = "(pipeline1|pipeline2)"
    pipeline_name = "pipeline"
    exclusions = {"pipeline1": {"SKIP_FILES": {"files": [".py", ".txt"]}}}
    agent_directory = "agent_directory"

    handle_remote_config_patterns_instance = HandleRemoteConfigPatterns(
        remote_config, exclusions, pipeline_name, agent_directory
    )
    result = handle_remote_config_patterns_instance.handle_bypass_expression(
        bypass_limits, pipeline_name
    )

    assert result == False


def test_process_handle_bypass_expression():
    with patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.usecases.handle_remote_config_patterns.HandleRemoteConfigPatterns.handle_bypass_expression"
    ) as mock_handle_bypass_expression:
        remote_config = {
            "remote_config_key": "remote_config_value",
            "BYPASS_ARCHIVE_LIMITS": "(pipeline1|pipeline2)",
        }
        pipeline_name = "pipeline_name"
        exclusions = {"pipeline1": {"SKIP_FILES": {"files": [".py", ".txt"]}}}
        agent_directory = "agent_directory"

        handle_remote_config_patterns_instance = HandleRemoteConfigPatterns(
            remote_config, exclusions, pipeline_name, agent_directory
        )
        handle_remote_config_patterns_instance.process_handle_bypass_expression()

        mock_handle_bypass_expression.assert_called_with(
            "(pipeline1|pipeline2)", pipeline_name
        )


def test_handle_skip_tool_skip():
    remote_config = {
        "remote_config_key": "remote_config_value",
    }
    exclusions = {"pipeline1": {"SKIP_TOOL": {"hu": ""}}}
    pipeline_name = "pipeline1"
    agent_directory = "agent_directory"

    handle_remote_config_patterns_instance = HandleRemoteConfigPatterns(
        remote_config, exclusions, pipeline_name, agent_directory
    )
    result = handle_remote_config_patterns_instance.handle_skip_tool(
        exclusions, pipeline_name
    )

    assert result == True


def test_handle_skip_tool_not_skip():
    remote_config = {
        "remote_config_key": "remote_config_value",
    }
    exclusions = {"pipeline1": {"SKIP_TOOL": {"hu": ""}}}
    pipeline_name = "pipeline"
    agent_directory = "agent_directory"

    handle_remote_config_patterns_instance = HandleRemoteConfigPatterns(
        remote_config, exclusions, pipeline_name, agent_directory
    )
    result = handle_remote_config_patterns_instance.handle_skip_tool(
        exclusions, pipeline_name
    )

    assert result == False


def test_process_handle_skip_tool():
    with patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.usecases.handle_remote_config_patterns.HandleRemoteConfigPatterns.handle_skip_tool"
    ) as mock_handle_skip_tool:
        remote_config = {
            "remote_config_key": "remote_config_value",
        }
        pipeline_name = "pipeline_name"
        exclusions = {"pipeline1": {"SKIP_TOOL": {"hu": ""}}}
        agent_directory = "agent_directory"

        handle_remote_config_patterns_instance = HandleRemoteConfigPatterns(
            remote_config, exclusions, pipeline_name, agent_directory
        )
        handle_remote_config_patterns_instance.process_handle_skip_tool()

        mock_handle_skip_tool.assert_called_with(exclusions, pipeline_name)


def test_handle_working_directory_agentdir():
    with patch("os.walk") as mock_walk:
        remote_config = {
            "remote_config_key": "remote_config_value",
            "ENGINE_DEPENDENCIES": {"ENABLED": "true"},
        }
        pipeline_name = "pipeline_name"
        exclusions = {"pipeline1": {"SKIP_TOOL": {"hu": ""}}}
        work_dir_different_flag = "test_dir"
        agent_directory = "/path/to/agent"
        mock_walk.return_value = [
            (agent_directory, ["dir1", "dir2"], ["file1.txt", "file2.json"]),
            (agent_directory + "/dir1", [], ["file3.ear"]),
            (agent_directory + "/dir2", ["test_dir"], ["file4.war"]),
        ]

        handle_remote_config_patterns_instance = HandleRemoteConfigPatterns(
            remote_config, exclusions, pipeline_name, agent_directory
        )
        result = handle_remote_config_patterns_instance.handle_working_directory(
            work_dir_different_flag, agent_directory
        )

        assert result == agent_directory


def test_handle_working_directory_workingdir():
    with patch("os.walk") as mock_walk, patch("os.getcwd") as mock_getcwd:
        remote_config = {
            "remote_config_key": "remote_config_value",
            "ENGINE_DEPENDENCIES": {"ENABLED": "true"},
        }
        pipeline_name = "pipeline_name"
        exclusions = {"pipeline1": {"SKIP_TOOL": {"hu": ""}}}
        mock_getcwd.return_value = "/path/to/working/dir"
        work_dir_different_flag = "test_dir"
        agent_directory = None
        mock_walk.return_value = [
            ("/agent_directory", ["dir1", "dir2"], ["file1.txt", "file2.json"]),
            ("/agent_directory" + "/dir1", [], ["file3.ear"]),
            ("/agent_directory" + "/dir2", ["test_dir"], ["file4.war"]),
        ]

        handle_remote_config_patterns_instance = HandleRemoteConfigPatterns(
            remote_config, exclusions, pipeline_name, agent_directory
        )
        result = handle_remote_config_patterns_instance.handle_working_directory(
            work_dir_different_flag, agent_directory
        )

        assert result == "/path/to/working/dir"


def test_process_handle_working_directory():
    with patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.usecases.handle_remote_config_patterns.HandleRemoteConfigPatterns.handle_working_directory"
    ) as mock_handle_working_directory:
        remote_config = {
            "remote_config_key": "remote_config_value",
            "WORK_DIR_DIFFERENT_FLAG": "test_dir",
        }
        agent_directory = "agent_directory"
        pipeline_name = "pipeline_name"
        exclusions = {"pipeline1": {"SKIP_TOOL": {"hu": ""}}}

        handle_remote_config_patterns_instance = HandleRemoteConfigPatterns(
            remote_config, exclusions, pipeline_name, agent_directory
        )
        handle_remote_config_patterns_instance.process_handle_working_directory()

        mock_handle_working_directory.assert_called_with("test_dir", agent_directory)
