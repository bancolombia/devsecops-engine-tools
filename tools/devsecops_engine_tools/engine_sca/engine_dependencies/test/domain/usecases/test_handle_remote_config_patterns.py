from devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.usecases.handle_remote_config_patterns import (
    HandleRemoteConfigPatterns,
)

from unittest.mock import patch


def test_init():
    remote_config = {"remote_config_key": "remote_config_value"}
    exclusions = {"Exclusion": "Exclusion_value"}
    pipeline_name = "pipeline"

    handle_remote_config_patterns_instance = HandleRemoteConfigPatterns(
        remote_config, exclusions, pipeline_name
    )

    assert handle_remote_config_patterns_instance.remote_config == remote_config
    assert handle_remote_config_patterns_instance.exclusions == exclusions
    assert handle_remote_config_patterns_instance.pipeline_name == pipeline_name


def test_excluded_files():
    remote_config = {
        "remote_config_key": "remote_config_value",
        "XRAY": {"REGEX_EXPRESSION_EXTENSIONS": ".js|.py|.txt"},
    }
    pipeline_name = "pipeline1"
    exclusions = {"pipeline1": {"SKIP_FILES": {"files": [".py", ".txt"]}}}
    expected_result = ".js"

    handle_remote_config_patterns_instance = HandleRemoteConfigPatterns(
        remote_config, exclusions, pipeline_name
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

    handle_remote_config_patterns_instance = HandleRemoteConfigPatterns(
        remote_config, exclusions, pipeline_name
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

    handle_remote_config_patterns_instance = HandleRemoteConfigPatterns(
        remote_config, exclusions, pipeline_name
    )
    result = handle_remote_config_patterns_instance.ignore_analysis_pattern()

    assert result == True


def test_skip_from_exclusion():
    remote_config = {
        "remote_config_key": "remote_config_value",
    }
    exclusions = {"pipeline1": {"SKIP_TOOL": {"hu": ""}}}
    pipeline_name = "pipeline1"

    handle_remote_config_patterns_instance = HandleRemoteConfigPatterns(
        remote_config, exclusions, pipeline_name
    )
    result = handle_remote_config_patterns_instance.skip_from_exclusion()

    assert result == True


def test_skip_from_exclusion_not_skip():
    remote_config = {
        "remote_config_key": "remote_config_value",
    }
    exclusions = {"pipeline1": {"SKIP_TOOL": {"hu": ""}}}
    pipeline_name = "pipeline"

    handle_remote_config_patterns_instance = HandleRemoteConfigPatterns(
        remote_config, exclusions, pipeline_name
    )
    result = handle_remote_config_patterns_instance.skip_from_exclusion()

    assert result == False
