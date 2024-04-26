from devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.usecases.find_artifacts import (
    FindArtifacts,
)

from unittest.mock import patch
import os
import subprocess


def test_init():
    working_dir = "/working/dir"
    pattern = "\\.(jar|ear|war)$"
    find_artifacts_instance = FindArtifacts(working_dir, pattern)

    assert find_artifacts_instance.working_dir == working_dir
    assert find_artifacts_instance.pattern == pattern


def test_find_packages():
    with patch("os.walk") as mock_walk, patch("os.path.join") as mock_join:
        working_dir = "/path/to/working_dir"
        mock_walk.return_value = [
            (working_dir, ["dir1", "dir2"], ["file1.txt", "file2.json"]),
            (working_dir, ["dir3"], ["file3.ear"]),
            (working_dir, ["node_modules"], ["file4.war"]),
            (working_dir, ["site-packages"], ["file5.jar"]),
        ]
        pattern = "\\.(jar|ear|war)$"

        find_artifacts_instance = FindArtifacts(working_dir, pattern)
        find_artifacts_instance.find_packages(pattern, working_dir)

        mock_join.assert_any_call


def test_get_recent_package():
    with patch("os.path.getctime") as mock_getctime:
        mock_getctime.return_value = 1

        packages = ["/path/to/dir1", "/path/to/dir2", "/path/to/dir3"]
        working_dir = "/path/to/working_dir"
        pattern = "\\.(jar|ear|war)$"

        find_artifacts_instance = FindArtifacts(working_dir, pattern)
        result = find_artifacts_instance.get_recent_package(packages)

        assert result == "/path/to/dir1"


def test_compress_and_mv_success():
    with patch("os.path.exists") as mock_exists, patch(
        "os.remove"
    ) as mock_remove, patch("tarfile.open") as mock_tarfile_open:
        package = "/path/to/package"
        tar_path = "/path/to/target_dir/package.tar"
        mock_exists.return_value = True
        working_dir = "/working/dir"
        pattern = "\\.(jar|ear|war)$"

        find_artifacts_instance = FindArtifacts(working_dir, pattern)
        find_artifacts_instance.compress_and_mv(tar_path, package)

        mock_remove.assert_called_with(tar_path)
        mock_tarfile_open.assert_called_with(tar_path, "w")


def test_compress_and_mv_failure():
    with patch("shutil.rmtree") as mock_rmtree, patch(
        "os.makedirs"
    ) as mock_makedirs, patch("os.path.exists") as mock_exists, patch(
        "os.remove"
    ) as mock_remove, patch(
        "tarfile.open"
    ) as mock_tarfile_open, patch(
        "os.path.basename"
    ) as mock_basename, patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.usecases.find_artifacts.logger.error"
    ) as mock_logger_error:
        package = "/path/to/package"
        tar_path = "/path/to/target_dir/package.tar"
        mock_exists.return_value = True
        mock_tarfile_open.side_effect = subprocess.CalledProcessError(
            returncode=1, cmd="opentar"
        )
        working_dir = "/working/dir"
        pattern = "\\.(jar|ear|war)$"

        find_artifacts_instance = FindArtifacts(working_dir, pattern)
        find_artifacts_instance.compress_and_mv(tar_path, package)

        mock_logger_error.assert_any_call


def test_move_files():
    with patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.usecases.find_artifacts.logger.debug"
    ) as mock_logger_debug:
        dir_to_scan_path = "/dir/to/scan"
        finded_files = [
            "/path/to/file1.txt",
            "/path/to/file2.txt",
            "/path/to/file3.txt",
        ]
        working_dir = "/working/dir"
        pattern = "\\.(jar|ear|war)$"

        mock_logger_debug.assert_any_call


def test_find_artifacts():
    with patch("os.path.join") as mock_join, patch(
        "os.path.exists"
    ) as mock_exists, patch("os.makedirs") as mock_makedirs, patch(
        "shutil.rmtree"
    ) as mock_rmtree, patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.usecases.find_artifacts.FindArtifacts.find_packages"
    ) as mock_find_packages, patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.usecases.find_artifacts.FindArtifacts.get_recent_package"
    ) as mock_get_recent_package, patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.usecases.find_artifacts.FindArtifacts.compress_and_mv"
    ) as mock_compress_and_mv, patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.usecases.find_artifacts.FindArtifacts.move_files"
    ) as mock_move_files:
        pattern = "\\.(jar|ear|war)$"
        working_dir = "/path/to/working_dir"
        mock_join.side_effect = lambda *args: "/".join(args)
        mock_exists.return_value = True
        mock_find_packages.return_value = (
            ["/path/to/node_modules"],
            ["/path/to/site-packages"],
            ["/path/to/file1"],
        )

        find_artifacts_instance = FindArtifacts(working_dir, pattern)
        find_artifacts_instance.find_artifacts()

        mock_rmtree.assert_called_once
        mock_makedirs.assert_called_once
        mock_find_packages.assert_called_once
        mock_get_recent_package.assert_any_call
        mock_join.assert_any_call
        mock_compress_and_mv.assert_any_call
        mock_move_files.assert_called_once
