from devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.usecases.handle_remote_config_patterns import (
    HandleRemoteConfigPatterns,
)

from unittest.mock import patch


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


def test_excluded_files():
    remote_config = {
        "remote_config_key": "remote_config_value",
        "REGEX_EXPRESSION_EXTENSIONS": ".js|.py|.txt",
    }
    pipeline_name = "pipeline1"
    exclusions = {"pipeline1": {"SKIP_FILES": {"files": [".py", ".txt"]}}}
    agent_directory = "agent_directory"
    expected_result = ".js"

    handle_remote_config_patterns_instance = HandleRemoteConfigPatterns(
        remote_config, exclusions, pipeline_name, agent_directory
    )
    result = handle_remote_config_patterns_instance.excluded_files()

    assert result == expected_result


def test_ignore_analysis_pattern_matched():
    remote_config = {
        "remote_config_key": "remote_config_value",
        "IGNORE_ANALYSIS_PATTERN": "(.*_test|Template_.*)",
    }
    pipeline_name = "pipeline_test"
    exclusions = {"pipeline1": {"SKIP_FILES": {"files": [".py", ".txt"]}}}
    agent_directory = "agent_directory"

    handle_remote_config_patterns_instance = HandleRemoteConfigPatterns(
        remote_config, exclusions, pipeline_name, agent_directory
    )
    result = handle_remote_config_patterns_instance.ignore_analysis_pattern()

    assert result == False


def test_ignore_analysis_pattern_matched():
    remote_config = {
        "remote_config_key": "remote_config_value",
        "IGNORE_ANALYSIS_PATTERN": "(.*_test|Template_.*)",
    }
    pipeline_name = "pipeline"
    exclusions = {"pipeline1": {"SKIP_FILES": {"files": [".py", ".txt"]}}}
    agent_directory = "agent_directory"

    handle_remote_config_patterns_instance = HandleRemoteConfigPatterns(
        remote_config, exclusions, pipeline_name, agent_directory
    )
    result = handle_remote_config_patterns_instance.ignore_analysis_pattern()

    assert result == True


def test_bypass_archive_limits_not_matched():
    remote_config = {
        "remote_config_key": "remote_config_value",
        "BYPASS_ARCHIVE_LIMITS": "(pipeline1|pipeline2)",
    }
    pipeline_name = "pipeline"
    exclusions = {"pipeline1": {"SKIP_FILES": {"files": [".py", ".txt"]}}}
    agent_directory = "agent_directory"

    handle_remote_config_patterns_instance = HandleRemoteConfigPatterns(
        remote_config, exclusions, pipeline_name, agent_directory
    )
    result = handle_remote_config_patterns_instance.bypass_archive_limits()

    assert result == False


def test_bypass_archive_limits_matched():
    remote_config = {
        "remote_config_key": "remote_config_value",
        "BYPASS_ARCHIVE_LIMITS": "(pipeline1|pipeline2)",
    }
    pipeline_name = "pipeline1"
    exclusions = {"pipeline1": {"SKIP_FILES": {"files": [".py", ".txt"]}}}
    agent_directory = "agent_directory"

    handle_remote_config_patterns_instance = HandleRemoteConfigPatterns(
        remote_config, exclusions, pipeline_name, agent_directory
    )
    result = handle_remote_config_patterns_instance.bypass_archive_limits()

    assert result == True


def test_skip_from_exclusion():
    remote_config = {
        "remote_config_key": "remote_config_value",
    }
    exclusions = {"pipeline1": {"SKIP_TOOL": {"hu": ""}}}
    pipeline_name = "pipeline1"
    agent_directory = "agent_directory"

    handle_remote_config_patterns_instance = HandleRemoteConfigPatterns(
        remote_config, exclusions, pipeline_name, agent_directory
    )
    result = handle_remote_config_patterns_instance.skip_from_exclusion()

    assert result == True


def test_skip_from_exclusion_not_skip():
    remote_config = {
        "remote_config_key": "remote_config_value",
    }
    exclusions = {"pipeline1": {"SKIP_TOOL": {"hu": ""}}}
    pipeline_name = "pipeline"
    agent_directory = "agent_directory"

    handle_remote_config_patterns_instance = HandleRemoteConfigPatterns(
        remote_config, exclusions, pipeline_name, agent_directory
    )
    result = handle_remote_config_patterns_instance.skip_from_exclusion()

    assert result == False


def test_different_working_directory_agentdir():
    with patch("os.walk") as mock_walk:
        remote_config = {
            "remote_config_key": "remote_config_value",
            "ENGINE_DEPENDENCIES": {"ENABLED": "true"},
            "WORK_DIR_DIFFERENT_FLAG": "test_dir",
        }
        pipeline_name = "pipeline_name"
        exclusions = {"pipeline1": {"SKIP_TOOL": {"hu": ""}}}
        agent_directory = "/path/to/agent"
        mock_walk.return_value = [
            (agent_directory, ["dir1", "dir2"], ["file1.txt", "file2.json"]),
            (agent_directory + "/dir1", [], ["file3.ear"]),
            (agent_directory + "/dir2", ["test_dir"], ["file4.war"]),
        ]

        handle_remote_config_patterns_instance = HandleRemoteConfigPatterns(
            remote_config, exclusions, pipeline_name, agent_directory
        )
        result = handle_remote_config_patterns_instance.different_working_directory()

        assert result == agent_directory


def test_different_working_directory_workingdir():
    with patch("os.walk") as mock_walk, patch("os.getcwd") as mock_getcwd:
        remote_config = {
            "remote_config_key": "remote_config_value",
            "ENGINE_DEPENDENCIES": {"ENABLED": "true"},
            "WORK_DIR_DIFFERENT_FLAG": "test_dir",
        }
        pipeline_name = "pipeline_name"
        exclusions = {"pipeline1": {"SKIP_TOOL": {"hu": ""}}}
        mock_getcwd.return_value = "/path/to/working/dir"
        agent_directory = None
        mock_walk.return_value = [
            ("/agent_directory", ["dir1", "dir2"], ["file1.txt", "file2.json"]),
            ("/agent_directory" + "/dir1", [], ["file3.ear"]),
            ("/agent_directory" + "/dir2", ["test_dir"], ["file4.war"]),
        ]

        handle_remote_config_patterns_instance = HandleRemoteConfigPatterns(
            remote_config, exclusions, pipeline_name, agent_directory
        )
        result = handle_remote_config_patterns_instance.different_working_directory()

        assert result == "/path/to/working/dir"
