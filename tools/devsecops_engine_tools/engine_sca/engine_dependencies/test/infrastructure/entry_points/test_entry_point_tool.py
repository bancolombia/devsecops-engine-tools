from devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.entry_points.entry_point_tool import (
    init_engine_dependencies,
)
from devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway import DevopsPlatformGateway
from devsecops_engine_tools.engine_core.src.domain.model.gateway.sbom_manager import SbomManagerGateway 
from unittest.mock import patch, Mock, MagicMock


def test_init_engine_dependencies():
    with patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.entry_points.entry_point_tool.DependenciesScan"
    ) as mock_dependencies_scan, patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.entry_points.entry_point_tool.SetInputCore"
    ) as mock_set_input_core, patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.entry_points.entry_point_tool.HandleRemoteConfigPatterns"
    ) as mock_handle_remote_config_patterns:
        dict_args = {"remote_config_repo": "remote_repo", "remote_config_branch": ""}
        token = "token"
        tool = {"ENGINE_DEPENDENCIES": {"TOOL": "tool"}, "SBOM_MANAGER": {"ENABLED": True, "BRANCH_FILTER": ["trunk"]}}
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
            Mock(),
            dict_args,
            token,
            tool,
            None
        )


@patch('devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.entry_points.entry_point_tool.HandleRemoteConfigPatterns')
@patch('devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.entry_points.entry_point_tool.SetInputCore')
@patch('devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.entry_points.entry_point_tool.DependenciesScan')
@patch('devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.entry_points.entry_point_tool.os.path.exists')
def test_init_engine_dependencies_success(mock_exists, mock_dependencies_scan, mock_set_input_core, mock_handle_remote_config_patterns):
    # Configurar los mocks
    mock_exists.return_value = True
    mock_handle_remote_config_patterns.return_value.skip_from_exclusion.return_value = False
    mock_handle_remote_config_patterns.return_value.ignore_analysis_pattern.return_value = True
    mock_dependencies_scan.return_value.process.return_value = "scanned_dependencies"
    mock_dependencies_scan.return_value.deserializator.return_value = ["deserialized_dependency"]
    mock_set_input_core.return_value.set_input_core.return_value = "core_input"

    # Crear mocks para las dependencias
    tool_run = MagicMock()
    tool_remote = MagicMock(spec=DevopsPlatformGateway)
    remote_config_source_gateway = MagicMock(spec=DevopsPlatformGateway)
    tool_remote.get_variable.return_value = "main"
    tool_deserializator = MagicMock()
    tool_sbom = MagicMock(spec=SbomManagerGateway)
    dict_args = {"remote_config_repo": "repo", "folder_path": "path", "remote_config_branch": ""}
    secret_tool = MagicMock()
    config_tool = {
        "SBOM_MANAGER": {"ENABLED": True, "BRANCH_FILTER": ["main"]},
        "ENGINE_DEPENDENCIES": {"TOOL": "tool"}
    }

    # Llamar a la función
    deserialized, core_input, sbom_components = init_engine_dependencies(
        tool_run, tool_remote, remote_config_source_gateway, tool_deserializator, dict_args, secret_tool, config_tool, tool_sbom
    )

    # Verificar que se llamaron las funciones esperadas
    remote_config_source_gateway.get_remote_config.assert_any_call("repo", "engine_sca/engine_dependencies/ConfigTool.json", "")
    remote_config_source_gateway.get_remote_config.assert_any_call("repo", "engine_sca/engine_dependencies/Exclusions.json", "")
    # tool_remote.get_variable.assert_called_with("pipeline_name")
    mock_handle_remote_config_patterns.assert_called_once()
    mock_dependencies_scan.return_value.process.assert_called_once()
    mock_dependencies_scan.return_value.deserializator.assert_called_once_with("scanned_dependencies")
    mock_set_input_core.return_value.set_input_core.assert_called_once_with("scanned_dependencies")

    assert deserialized, ["deserialized_dependency"]
    assert core_input, "core_input"
    assert sbom_components is not None