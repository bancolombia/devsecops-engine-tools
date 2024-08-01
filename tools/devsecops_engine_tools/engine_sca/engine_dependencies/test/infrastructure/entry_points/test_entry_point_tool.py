from devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.entry_points.entry_point_tool import (
    init_engine_dependencies,
)

from unittest.mock import patch, Mock


def test_init_engine_dependencies():
    with patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.entry_points.entry_point_tool.DependenciesScan"
    ) as mock_dependencies_scan, patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.entry_points.entry_point_tool.SetInputCore"
    ) as mock_set_input_core, patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.entry_points.entry_point_tool.HandleRemoteConfigPatterns"
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
        mock_dependencies_scan.process.return_value = "scan_result.json"

        init_engine_dependencies(
            Mock(),
            Mock(),
            Mock(),
            dict_args,
            token,
            tool,
        )
