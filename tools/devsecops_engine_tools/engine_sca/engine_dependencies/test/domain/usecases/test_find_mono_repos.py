from devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.usecases.find_mono_repos import (
    FindMonoRepos,
)

from unittest.mock import patch


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
        find_mono_repos_instance.find_mono_repo()

        mock_walk.assert_called_once()
