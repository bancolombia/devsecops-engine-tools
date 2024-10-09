from devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.helpers.get_artifacts import (
    GetArtifacts,
)

import subprocess
import pytest
from unittest.mock import patch, Mock


@pytest.fixture
def get_artifacts_instance():
    return GetArtifacts()


def test_excluded_files(get_artifacts_instance):
    remote_config = {
        "remote_config_key": "remote_config_value",
        "XRAY": {"REGEX_EXPRESSION_EXTENSIONS": ".js|.py|.txt"},
    }
    pipeline_name = "pipeline1"
    exclusions = {"pipeline1": {"XRAY": [{"SKIP_FILES": {"files": [".py", ".txt"]}}]}}
    expected_result = ".js"

    result = get_artifacts_instance.excluded_files(
        remote_config, pipeline_name, exclusions, "XRAY"
    )

    assert result == expected_result


def test_find_packages(get_artifacts_instance):
    with patch("os.walk") as mock_walk, patch("os.path.join") as mock_join:
        working_dir = "/path/to/working_dir"
        mock_walk.return_value = [
            (working_dir, ["dir1", "dir2"], ["file1.txt", "file2.json"]),
            (working_dir, ["dir3"], ["file3.ear"]),
            (working_dir, ["node_modules"], ["file4.war"]),
            (working_dir, ["site-packages"], ["file5.jar"]),
        ]
        pattern = "\\.(jar|ear|war)$"
        packages = ["package"]

        get_artifacts_instance.find_packages(pattern, packages, working_dir)

        mock_join.assert_any_call


def test_compress_and_mv_success(get_artifacts_instance):
    with patch("tarfile.open") as mock_tarfile_open:
        package = "/path/to/package"
        tar_path = "/path/to/target_dir/package.tar"

        get_artifacts_instance.compress_and_mv(tar_path, package)

        mock_tarfile_open.assert_called_with(tar_path, "w")


def test_compress_and_mv_failure(get_artifacts_instance):
    with patch("tarfile.open") as mock_tarfile_open, patch(
        "os.path.basename"
    ) as mock_basename, patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.helpers.get_artifacts.logger.error"
    ) as mock_logger_error:
        package = "/path/to/package"
        tar_path = "/path/to/target_dir/package.tar"
        mock_tarfile_open.side_effect = subprocess.CalledProcessError(
            returncode=1, cmd="opentar"
        )

        get_artifacts_instance.compress_and_mv(tar_path, package)

        mock_logger_error.assert_any_call


def test_move_files(get_artifacts_instance):
    with patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.helpers.get_artifacts.logger.debug"
    ) as mock_logger_debug, patch("os.path.join") as mock_path_join, patch(
        "shutil.copy2"
    ) as mock_copy:
        dir_to_scan_path = "/dir/to/scan"
        finded_files = [
            "/path/to/file1.txt",
            "/path/to/file2.txt",
            "/path/to/file3.txt",
        ]

        get_artifacts_instance.move_files(dir_to_scan_path, finded_files)

        mock_logger_debug.assert_any_call


def test_find_artifacts(get_artifacts_instance):
    with patch("os.path.join") as mock_join, patch(
        "os.path.exists"
    ) as mock_exists, patch("os.makedirs") as mock_makedirs, patch(
        "shutil.rmtree"
    ) as mock_rmtree, patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.helpers.get_artifacts.GetArtifacts.find_packages"
    ) as mock_find_packages, patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.helpers.get_artifacts.GetArtifacts.compress_and_mv"
    ) as mock_compress_and_mv, patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.helpers.get_artifacts.GetArtifacts.move_files"
    ) as mock_move_files, patch(
        "os.listdir"
    ) as mock_listdir, patch(
        "os.path.isfile"
    ) as mock_isfile, patch(
        "os.path.join"
    ) as mock_path_join, patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.helpers.get_artifacts.logger.debug"
    ) as mock_logger:
        pattern = "\\.(jar|ear|war)$"
        to_scan = "/path/to/working_dir"
        packages = ["package"]
        mock_join.side_effect = lambda *args: "/".join(args)
        mock_exists.return_value = True
        mock_find_packages.return_value = (
            ["/path/to/node_modules"],
            ["/path/to/file1"],
        )
        mock_listdir.return_value = ["package1"]
        mock_isfile.return_value = True

        get_artifacts_instance.find_artifacts(to_scan, pattern, packages)

        mock_rmtree.assert_called_once
        mock_makedirs.assert_called_once
        mock_find_packages.assert_called_once
        mock_join.assert_any_call
        mock_compress_and_mv.assert_any_call
        mock_move_files.assert_called_once
        mock_logger.assert_called_once
