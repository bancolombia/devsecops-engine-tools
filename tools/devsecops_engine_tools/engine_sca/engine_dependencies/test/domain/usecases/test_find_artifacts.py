from devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.usecases.find_artifacts import (
    FindArtifacts,
)

import pytest
from unittest.mock import mock_open, patch, Mock
import os
import subprocess


def test_init():
    working_dir = "/working/dir"
    pattern = "\\.(jar|ear|war)$"
    find_artifacts_instance = FindArtifacts(working_dir, pattern)

    assert find_artifacts_instance.working_dir == working_dir
    assert find_artifacts_instance.pattern == pattern


def test_find_node_modules_finded():
    with patch("os.walk") as mock_walk, patch("os.path.join") as mock_path_join:
        working_dir = "/path/to/working_dir"
        mock_walk.return_value = [
            (working_dir, ["dir1", "dir2"], ["file1.txt", "file2.json"]),
            (working_dir + "/dir1", [], ["file3.ear"]),
            (working_dir + "/node_modules", [], ["file4.war"]),
        ]
        working_dir = "/working/dir"
        pattern = "\\.(jar|ear|war)$"

        find_artifacts_instance = FindArtifacts(working_dir, pattern)
        find_artifacts_instance.find_node_modules(working_dir)

        mock_path_join.assert_any_call


def test_find_node_modules_not_finded():
    with patch("os.walk") as mock_walk, patch("os.path.join") as mock_path_join:
        working_dir = "/path/to/working_dir"
        mock_walk.return_value = [
            (working_dir, ["dir1", "dir2"], ["file1.txt", "file2.json"]),
            (working_dir + "/dir1", [], ["file3.ear"]),
            (working_dir + "/dir2", [], ["file4.war"]),
        ]
        working_dir = "/working/dir"
        pattern = "\\.(jar|ear|war)$"

        find_artifacts_instance = FindArtifacts(working_dir, pattern)
        find_artifacts_instance.find_node_modules(working_dir)

        mock_path_join.assert_not_called


def test_compress_and_mv_success():
    with patch("os.path.exists") as mock_exists, patch(
        "os.remove"
    ) as mock_remove, patch("tarfile.open") as mock_tarfile_open:
        npm_modules = "/path/to/npm_modules"
        target_dir = "/path/to/target_dir"
        mock_exists.return_value = True
        working_dir = "/working/dir"
        pattern = "\\.(jar|ear|war)$"

        find_artifacts_instance = FindArtifacts(working_dir, pattern)
        find_artifacts_instance.compress_and_mv(npm_modules, target_dir)

        mock_remove.assert_called_with(os.path.join(target_dir, "node_modules.tar"))
        mock_tarfile_open.assert_called_with(
            os.path.join(target_dir, "node_modules.tar"), "w"
        )


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
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.prisma_cloud.prisma_cloud_manager_scan.logger.error"
    ) as mock_logger_error:
        npm_modules = "/path/to/npm_modules"
        target_dir = "/path/to/target_dir"
        mock_exists.return_value = True
        mock_tarfile_open.side_effect = subprocess.CalledProcessError(
            returncode=1, cmd="opentar"
        )
        working_dir = "/working/dir"
        pattern = "\\.(jar|ear|war)$"

        find_artifacts_instance = FindArtifacts(working_dir, pattern)
        find_artifacts_instance.compress_and_mv(npm_modules, target_dir)

        mock_logger_error.assert_called_with(
            "Error during npm_modules compression: Command 'opentar' returned non-zero exit status 1."
        )


def test_find_by_extension():
    with patch("shutil.copy2") as mock_copy2, patch("os.walk") as mock_walk, patch(
        "os.path.join"
    ) as mock_path_join:
        pattern = "\\.(jar|ear|war)$"
        working_dir = "/path/to/working_dir"
        target_dir = "/path/to/target_dir"
        excluded_dir = ""
        mock_walk.return_value = [
            ("/path/to/working_dir", ["dir1", "dir2"], ["file1.txt", "file2.json"]),
            ("/path/to/working_dir/dir1", [], ["file3.ear"]),
            ("/path/to/working_dir/dir2", [], ["file4.war"]),
        ]

        find_artifacts_instance = FindArtifacts(working_dir, pattern)
        find_artifacts_instance.find_by_extension(
            pattern, working_dir, target_dir, excluded_dir
        )

        mock_path_join.assert_any_call
        mock_copy2.assert_any_call


def test_find_artifacts_():
    with patch("os.path.join") as mock_join, patch(
        "os.path.exists"
    ) as mock_exists, patch("os.makedirs") as mock_makedirs, patch(
        "shutil.rmtree"
    ) as mock_rmtree, patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.usecases.find_artifacts.FindArtifacts.find_node_modules"
    ) as mock_find_node_modules, patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.usecases.find_artifacts.FindArtifacts.compress_and_mv"
    ) as mock_compress_and_mv, patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.usecases.find_artifacts.FindArtifacts.find_by_extension"
    ) as mock_find_by_extension:
        pattern = "\\.(jar|ear|war)$"
        working_dir = "/path/to/working_dir"
        mock_join.side_effect = lambda *args: "/".join(args)
        mock_exists.return_value = True
        mock_find_node_modules.return_value = "/path/to/node_modules"

        find_artifacts_instance = FindArtifacts(working_dir, pattern)
        find_artifacts_instance.find_artifacts()

        mock_rmtree.assert_any_call
        mock_makedirs.assert_any_call
        mock_find_node_modules.assert_called_with(working_dir)
        mock_compress_and_mv.assert_any_call
        mock_find_by_extension.assert_called_with(
            pattern,
            working_dir,
            working_dir + "/dependencies_to_scan",
            "/path/to/node_modules",
        )
