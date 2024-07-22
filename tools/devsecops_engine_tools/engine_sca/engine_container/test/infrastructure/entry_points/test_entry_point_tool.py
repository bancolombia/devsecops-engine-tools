from devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.entry_points.entry_point_tool import (
    init_engine_sca_rm,
)
from unittest.mock import patch, Mock
import pytest


def test_init_engine_sca_rm():
    with patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.entry_points.entry_point_tool.ContainerScaScan"
    ) as mock_container_sca_scan, patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.entry_points.entry_point_tool.SetInputCore"
    ) as mock_set_input_core, patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.entry_points.entry_point_tool.HandleRemoteConfigPatterns"
    ) as mock_handle_remote_config_patterns:
        dict_args = {"remote_config_repo": "remote_repo"}
        token = "token"
        tool = "tool"
        mock_handle_remote_config_patterns.process_handle_working_directory.return_value = (
            "working_dir"
        )
        mock_handle_remote_config_patterns.process_handle_skip_tool.return_value = False
        mock_handle_remote_config_patterns.process_handle_analysis_pattern.return_value = (
            True
        )
        mock_container_sca_scan.process.return_value = "scan_result.json"

        deserialized, core_input = init_engine_sca_rm(
            Mock(),
            Mock(),
            Mock(),
            Mock(),
            dict_args,
            token,
            tool,
        )


def test_init_engine_sca_rm_skip_tool():
    with patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.entry_points.entry_point_tool.ContainerScaScan"
    ) as mock_container_sca_scan, patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.entry_points.entry_point_tool.SetInputCore"
    ) as mock_set_input_core, patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.entry_points.entry_point_tool.HandleRemoteConfigPatterns"
    ) as mock_handle_remote_config_patterns:
        dict_args = {"remote_config_repo": "remote_repo"}
        token = "token"
        tool = "tool"
        mock_handle_remote_config_patterns.process_handle_working_directory.return_value = (
            "working_dir"
        )
        mock_handle_remote_config_patterns.process_handle_skip_tool.return_value = True
        mock_handle_remote_config_patterns.process_handle_analysis_pattern.return_value = (
            True
        )

        deserialized, core_input = init_engine_sca_rm(
            Mock(),
            Mock(),
            Mock(),
            Mock(),
            dict_args,
            token,
            tool,
        )
        assert deserialized == []
        mock_container_sca_scan.assert_not_called()


def test_init_engine_sca_rm_no_exclusions():
    with patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.entry_points.entry_point_tool.ContainerScaScan"
    ) as mock_container_sca_scan, patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.entry_points.entry_point_tool.SetInputCore"
    ) as mock_set_input_core, patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.entry_points.entry_point_tool.HandleRemoteConfigPatterns"
    ) as mock_handle_remote_config_patterns:
        dict_args = {"remote_config_repo": "remote_repo"}
        token = "token"
        tool = "tool"
        mock_handle_remote_config_patterns.process_handle_working_directory.return_value = (
            "working_dir"
        )
        mock_handle_remote_config_patterns.process_handle_skip_tool.return_value = False
        mock_handle_remote_config_patterns.process_handle_analysis_pattern.return_value = (
            False
        )
        mock_container_sca_scan.process.return_value = "scan_result.json"

        deserialized, core_input = init_engine_sca_rm(
            Mock(),
            Mock(),
            Mock(),
            Mock(),
            dict_args,
            token,
            tool,
        )
        assert deserialized == []
        mock_container_sca_scan.assert_not_called()


def test_init_engine_sca_rm_empty_remote_config():
    with patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.entry_points.entry_point_tool.ContainerScaScan"
    ) as mock_container_sca_scan, patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.entry_points.entry_point_tool.SetInputCore"
    ) as mock_set_input_core, patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.entry_points.entry_point_tool.HandleRemoteConfigPatterns"
    ) as mock_handle_remote_config_patterns:
        dict_args = {"remote_config_repo": "remote_repo"}
        token = "token"
        tool = "tool"
        mock_handle_remote_config_patterns.process_handle_working_directory.return_value = (
            "working_dir"
        )
        mock_handle_remote_config_patterns.process_handle_skip_tool.return_value = False
        mock_handle_remote_config_patterns.process_handle_analysis_pattern.return_value = (
            True
        )
        mock_container_sca_scan.process.return_value = "scan_result.json"

        deserialized, core_input = init_engine_sca_rm(
            Mock(),
            Mock(),
            Mock(),
            Mock(),
            dict_args,
            token,
            tool,
        )
