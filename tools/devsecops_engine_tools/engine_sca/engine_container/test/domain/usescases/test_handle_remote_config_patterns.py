import pytest
from devsecops_engine_tools.engine_sca.engine_container.src.domain.usecases.handle_remote_config_patterns import (
    HandleRemoteConfigPatterns,
)


@pytest.fixture
def remote_config():
    return {"IGNORE_SEARCH_PATTERN": "ignore_this_pipeline"}


@pytest.fixture
def exclusions():
    return {"dummy_pipeline": {"SKIP_TOOL": 1}}


@pytest.fixture
def handle_remote(remote_config, exclusions):
    return HandleRemoteConfigPatterns(remote_config, exclusions, "dummy_pipeline")


def test_ignore_analysis_pattern_false(handle_remote):
    handle_remote.pipeline_name = "ignore_this_pipeline"
    assert not handle_remote.ignore_analysis_pattern()


def test_ignore_analysis_pattern_true(handle_remote):
    handle_remote.pipeline_name = "do_not_ignore_this_pipeline"
    assert handle_remote.ignore_analysis_pattern()


def test_skip_from_exclusion(handle_remote):
    assert handle_remote.skip_from_exclusion()


def test_not_skip_from_exclusion(handle_remote):
    handle_remote.pipeline_name = "another_pipeline"
    assert not handle_remote.skip_from_exclusion()
