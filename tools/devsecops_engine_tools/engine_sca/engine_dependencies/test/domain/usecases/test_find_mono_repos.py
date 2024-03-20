from devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.usecases.find_mono_repos import (
    FindMonoRepos,
)

import pytest
from unittest.mock import mock_open, patch, Mock


def test_init():
    pipeline_name = "pipeline"

    find_mono_repos_instance = FindMonoRepos(pipeline_name)

    assert find_mono_repos_instance.pipeline_name == pipeline_name


def test_handle_find_mono_repo():
    with patch("os.walk") as mock_walk:
        work_dir = "/path/to/dir"
        mock_walk.return_value = [
            (work_dir, ["dir1", "dir_name"], ["file1.txt", "file2.json"]),
            (work_dir + "/dir1", [], ["file3.ear"]),
            (work_dir + "/dir2", ["test_dir"], ["file4.war"]),
        ]
        pipeline_name = "pipeline_MR_test_dir"

        find_mono_repos_instance = FindMonoRepos(pipeline_name)
        find_mono_repos_instance.handle_find_mono_repo(pipeline_name)

        mock_walk.assert_called_once()


def test_process_find_mono_repo():
    with patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.usecases.find_mono_repos.FindMonoRepos.handle_find_mono_repo"
    ) as mock_handle_find_mono_repo, patch("os.walk") as mock_walk:
        work_dir = "/path/to/dir"
        mock_walk.return_value = [
            (work_dir, ["dir1", "dir_name"], ["file1.txt", "file2.json"]),
            (work_dir + "/dir1", [], ["file3.ear"]),
            (work_dir + "/dir2", ["test_dir"], ["file4.war"]),
        ]
        pipeline_name = "pipeline"

        find_mono_repos_instance = FindMonoRepos(pipeline_name)
        find_mono_repos_instance.process_find_mono_repo()

        mock_handle_find_mono_repo.get_variable.assert_any_call
