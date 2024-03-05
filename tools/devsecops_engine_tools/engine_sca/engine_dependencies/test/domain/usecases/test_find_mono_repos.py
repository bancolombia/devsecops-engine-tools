from devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.usecases.find_mono_repos import (
    FindMonoRepos,
)

import pytest
from unittest.mock import mock_open, patch, Mock

def test_init():
    with patch(
        "devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway.DevopsPlatformGateway"
    ) as mock_tool_remote:
        find_mono_repos_instance = FindMonoRepos(
            mock_tool_remote
        )

        assert find_mono_repos_instance.tool_remote == mock_tool_remote

def test_get_variable():
    with patch(
        "devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway.DevopsPlatformGateway"
    ) as mock_tool_remote:
        variable = "test_variable"
        find_mono_repos_instance = FindMonoRepos(
            mock_tool_remote
        )
        find_mono_repos_instance.get_variable(variable)

        mock_tool_remote.get_variable.assert_called_once_with(variable)

def test_find_mono_repo():
    with patch(
        "devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway.DevopsPlatformGateway"
    ) as mock_tool_remote, patch("os.walk") as mock_walk:
        # mock_tool_remote.get_variable.return_value = "pipeline_MR_dir_name"
        work_dir = "/path/to/dir"
        mock_walk.return_value = [
            (work_dir, ["dir1", "dir_name"], ["file1.txt", "file2.json"]),
            (work_dir + "/dir1", [], ["file3.ear"]),
            (work_dir + "/dir2", ["test_dir"], ["file4.war"]),
        ]
        find_mono_repos_instance = FindMonoRepos(
            mock_tool_remote
        )
        result = find_mono_repos_instance.handle_find_mono_repo("pipeline_MR_dir_name")

        assert result == work_dir+"\dir_name"


def test_process_find_mono_repo():
    with patch(
        "devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway.DevopsPlatformGateway"
    ) as mock_tool_remote, patch("os.walk") as mock_walk:
        mock_tool_remote.get_variable.return_value = "pipeline_MR_dir_name"
        work_dir = "/path/to/dir"
        mock_walk.return_value = [
            (work_dir, ["dir1", "dir_name"], ["file1.txt", "file2.json"]),
            (work_dir + "/dir1", [], ["file3.ear"]),
            (work_dir + "/dir2", ["test_dir"], ["file4.war"]),
        ]
        find_mono_repos_instance = FindMonoRepos(
            mock_tool_remote
        )
        result = find_mono_repos_instance.process_find_mono_repo()

        mock_tool_remote.get_variable.assert_any_call