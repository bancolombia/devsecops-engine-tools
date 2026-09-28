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
        tool = {
            "ENGINE_DEPENDENCIES": {"TOOL": "tool"},
            "SBOM_MANAGER": {"ENABLED": True, "BRANCH_FILTER": ["trunk"]},
            "LICENSE_ANALYZER": {"TOOL": "dep_track"},
        }
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
            None,
            Mock(),
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
        "ENGINE_DEPENDENCIES": {"TOOL": "tool"},
        "LICENSE_ANALYZER": {"TOOL": "dep_track"},
    }

    # Llamar a la función
    deserialized, core_input, sbom_components = init_engine_dependencies(
        tool_run, tool_remote, remote_config_source_gateway, tool_deserializator, dict_args, secret_tool, config_tool, tool_sbom, Mock()
    )

    # Verificar que se llamaron las funciones esperadas
    remote_config_source_gateway.get_remote_config.assert_any_call("repo", "engine_sca/engine_dependencies/ConfigTool.json", "")
    remote_config_source_gateway.get_remote_config.assert_any_call("repo", "engine_sca/engine_dependencies/Exclusions.json", "")
    mock_handle_remote_config_patterns.assert_called_once()
    mock_dependencies_scan.return_value.process.assert_called_once()
    mock_dependencies_scan.return_value.deserializator.assert_called_once_with("scanned_dependencies")
    mock_set_input_core.return_value.set_input_core.assert_called_once_with("scanned_dependencies")

    assert deserialized, ["deserialized_dependency"]
    assert core_input, "core_input"
    assert sbom_components is not None


@patch('devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.entry_points.entry_point_tool.HandleRemoteConfigPatterns')
@patch('devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.entry_points.entry_point_tool.SetInputCore')
@patch('devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.entry_points.entry_point_tool.DependenciesScan')
@patch('devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.entry_points.entry_point_tool.os.path.isfile')
@patch('devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.entry_points.entry_point_tool.os.path.exists')
@patch('devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.entry_points.entry_point_tool.get_list_component')
def test_init_engine_dependencies_with_existing_sbom(mock_get_list_component, mock_exists, mock_isfile, mock_dependencies_scan, mock_set_input_core, mock_handle_remote_config_patterns):
    mock_exists.return_value = True
    mock_isfile.return_value = True
    mock_handle_remote_config_patterns.return_value.skip_from_exclusion.return_value = False
    mock_handle_remote_config_patterns.return_value.ignore_analysis_pattern.return_value = True
    mock_dependencies_scan.return_value.process.return_value = "scanned_dependencies"
    mock_dependencies_scan.return_value.deserializator.return_value = []
    mock_get_list_component.return_value = [Mock()]

    tool_remote = MagicMock(spec=DevopsPlatformGateway)
    tool_remote.get_variable.return_value = "main"
    remote_config_source_gateway = MagicMock(spec=DevopsPlatformGateway)
    tool_sbom = MagicMock(spec=SbomManagerGateway)
    config_tool = {
        "SBOM_MANAGER": {"ENABLED": True, "BRANCH_FILTER": ["main"]},
        "ENGINE_DEPENDENCIES": {"TOOL": "tool"},
        "LICENSE_ANALYZER": {"TOOL": "dep_track"},
    }
    sbom_path = "/tmp/existing_SBOM.json"
    dict_args = {"remote_config_repo": "repo", "folder_path": sbom_path, "remote_config_branch": ""}

    init_engine_dependencies(
        Mock(), tool_remote, remote_config_source_gateway, Mock(), dict_args,
        None, config_tool, tool_sbom, Mock()
    )

    mock_get_list_component.assert_called_once_with(sbom_path)
    tool_sbom.get_components.assert_not_called()


@patch('devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.entry_points.entry_point_tool.HandleRemoteConfigPatterns')
@patch('devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.entry_points.entry_point_tool.SetInputCore')
@patch('devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.entry_points.entry_point_tool.DependenciesScan')
@patch('devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.entry_points.entry_point_tool.os.path.isfile')
@patch('devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.entry_points.entry_point_tool.os.path.exists')
def test_generate_sbom_without_dependency_scan(mock_exists, mock_isfile, mock_dependencies_scan, mock_set_input_core, mock_handle_remote_config_patterns):
    mock_exists.return_value = True
    mock_isfile.return_value = False
    mock_handle_remote_config_patterns.return_value.skip_from_exclusion.return_value = False
    mock_handle_remote_config_patterns.return_value.ignore_analysis_pattern.return_value = True
    mock_set_input_core.return_value.set_input_core.return_value = "core_input"

    tool_remote = MagicMock(spec=DevopsPlatformGateway)
    tool_remote.get_variable.return_value = "main"
    remote_config_source_gateway = MagicMock(spec=DevopsPlatformGateway)
    tool_sbom = MagicMock(spec=SbomManagerGateway)
    tool_sbom.get_components.return_value = [Mock()]
    tool_license_manager = Mock()
    tool_license_manager.upload_sbom.return_value = "task-id"
    config_tool = {
        "SBOM_MANAGER": {"ENABLED": True, "BRANCH_FILTER": ["main"]},
        "ENGINE_DEPENDENCIES": {"TOOL": "trivy"},
        "LICENSE_ANALYZER": {
            "TOOL": "dep_track",
            "dep_track": {
                "API_KEY_SECRET_KEY": "license-token",
                "HOST": "https://dependency-track.example",
                "EXPORT_TASK_ID": False,
            },
        },
    }
    dict_args = {
        "remote_config_repo": "repo",
        "folder_path": "/project",
        "remote_config_branch": "",
        "generate_sbom_only": "true",
        "use_license_analyzer": "true",
        "token_license_analyzer": "license-api-key",
    }

    with patch('devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.entry_points.entry_point_tool.logger') as mock_logger:
        deserialized, core_input, sbom_components = init_engine_dependencies(
            Mock(), tool_remote, remote_config_source_gateway, Mock(), dict_args,
            None, config_tool, tool_sbom, tool_license_manager
        )

    tool_sbom.get_components.assert_called_once_with(
        "/project", config_tool["SBOM_MANAGER"], "main"
    )
    mock_dependencies_scan.assert_not_called()
    mock_logger.info.assert_any_call(
        "Dependency vulnerability scan skipped for this execution. (Only SBOM generation)"
    )
    tool_license_manager.upload_sbom.assert_called_once()
    assert deserialized == []
    assert core_input == "core_input"
    assert sbom_components == tool_sbom.get_components.return_value


@patch('devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.entry_points.entry_point_tool.HandleRemoteConfigPatterns')
@patch('devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.entry_points.entry_point_tool.SetInputCore')
def test_init_engine_dependencies_skip_tool(mock_set_input_core, mock_handle_remote_config_patterns):
    """Covers else branch: scan_flag=False → 'Tool skipped by DevSecOps policy'."""
    mock_handle_remote_config_patterns.return_value.skip_from_exclusion.return_value = False
    mock_handle_remote_config_patterns.return_value.ignore_analysis_pattern.return_value = False  # scan_flag = False

    tool_remote = MagicMock(spec=DevopsPlatformGateway)
    tool_remote.get_variable.return_value = "main"
    remote_config_source_gateway = MagicMock(spec=DevopsPlatformGateway)
    mock_set_input_core.return_value.set_input_core.return_value = "core_input"

    config_tool = {
        "SBOM_MANAGER": {"ENABLED": False, "BRANCH_FILTER": []},
        "ENGINE_DEPENDENCIES": {"TOOL": "tool"},
        "LICENSE_ANALYZER": {"TOOL": "dep_track"},
    }
    dict_args = {"remote_config_repo": "repo", "folder_path": None, "remote_config_branch": ""}

    deserialized, core_input, sbom_components = init_engine_dependencies(
        Mock(), tool_remote, remote_config_source_gateway, Mock(), dict_args,
        None, config_tool, Mock(), Mock()
    )

    assert deserialized == []
    assert sbom_components is None
    assert dict_args["send_metrics"] == "false"
    assert dict_args["use_vulnerability_management"] == "false"


@patch('devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.entry_points.entry_point_tool.HandleRemoteConfigPatterns')
@patch('devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.entry_points.entry_point_tool.SetInputCore')
@patch('devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.entry_points.entry_point_tool.os.path.exists')
@patch('devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.entry_points.entry_point_tool.logger')
def test_init_engine_dependencies_path_not_exists(mock_logger, mock_exists, mock_set_input_core, mock_handle_remote_config_patterns):
    """Covers logger.error when the target scan path does not exist."""
    mock_exists.return_value = False
    mock_handle_remote_config_patterns.return_value.skip_from_exclusion.return_value = False
    mock_handle_remote_config_patterns.return_value.ignore_analysis_pattern.return_value = True
    mock_set_input_core.return_value.set_input_core.return_value = "core_input"

    tool_remote = MagicMock(spec=DevopsPlatformGateway)
    tool_remote.get_variable.return_value = "main"
    remote_config_source_gateway = MagicMock(spec=DevopsPlatformGateway)

    config_tool = {
        "SBOM_MANAGER": {"ENABLED": False, "BRANCH_FILTER": []},
        "ENGINE_DEPENDENCIES": {"TOOL": "tool"},
        "LICENSE_ANALYZER": {"TOOL": "dep_track"},
    }
    dict_args = {"remote_config_repo": "repo", "folder_path": "nonexistent_path", "remote_config_branch": ""}

    deserialized, core_input, sbom_components = init_engine_dependencies(
        Mock(), tool_remote, remote_config_source_gateway, Mock(), dict_args,
        None, config_tool, Mock(), Mock()
    )

    mock_logger.error.assert_called_once_with("Path nonexistent_path does not exist")
    assert deserialized == []
    assert sbom_components is None


@patch('devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.entry_points.entry_point_tool.HandleRemoteConfigPatterns')
@patch('devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.entry_points.entry_point_tool.SetInputCore')
@patch('devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.entry_points.entry_point_tool.DependenciesScan')
@patch('devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.entry_points.entry_point_tool.os.path.exists')
@patch('devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.entry_points.entry_point_tool.logger')
def test_init_engine_dependencies_license_no_token(mock_logger, mock_exists, mock_dependencies_scan, mock_set_input_core, mock_handle_remote_config_patterns):
    """Covers --use_license_analyzer=true but no token → logger.error."""
    mock_exists.return_value = True
    mock_handle_remote_config_patterns.return_value.skip_from_exclusion.return_value = False
    mock_handle_remote_config_patterns.return_value.ignore_analysis_pattern.return_value = True
    mock_dependencies_scan.return_value.process.return_value = "scanned_dependencies"
    mock_dependencies_scan.return_value.deserializator.return_value = ["dep"]
    mock_set_input_core.return_value.set_input_core.return_value = "core_input"

    tool_remote = MagicMock(spec=DevopsPlatformGateway)
    tool_remote.get_variable.return_value = "main"
    remote_config_source_gateway = MagicMock(spec=DevopsPlatformGateway)
    tool_sbom = MagicMock(spec=SbomManagerGateway)
    tool_sbom.get_components.return_value = [Mock()]

    config_tool = {
        "SBOM_MANAGER": {"ENABLED": True, "BRANCH_FILTER": ["main"]},
        "ENGINE_DEPENDENCIES": {"TOOL": "tool"},
        "LICENSE_ANALYZER": {
            "TOOL": "dep_track",
            "dep_track": {
                "API_KEY_SECRET_KEY": "api_key_secret",
                "HOST": "http://host",
                "EXPORT_TASK_ID": False,
            },
        },
    }
    dict_args = {"remote_config_repo": "repo", "folder_path": "path", "remote_config_branch": "", "use_license_analyzer": "true"}

    # secret_tool=None and no token_license_analyzer in dict_args → token is None
    init_engine_dependencies(
        Mock(), tool_remote, remote_config_source_gateway, Mock(), dict_args,
        None, config_tool, tool_sbom, Mock()
    )

    mock_logger.error.assert_any_call("API key for license analyzer is not provided.")


@patch('devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.entry_points.entry_point_tool.HandleRemoteConfigPatterns')
@patch('devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.entry_points.entry_point_tool.SetInputCore')
@patch('devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.entry_points.entry_point_tool.DependenciesScan')
@patch('devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.entry_points.entry_point_tool.os.path.exists')
@patch('devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.entry_points.entry_point_tool.logger')
def test_init_engine_dependencies_license_upload_with_export_task_id(mock_logger, mock_exists, mock_dependencies_scan, mock_set_input_core, mock_handle_remote_config_patterns):
    """Covers full license upload path including EXPORT_TASK_ID."""
    mock_exists.return_value = True
    mock_handle_remote_config_patterns.return_value.skip_from_exclusion.return_value = False
    mock_handle_remote_config_patterns.return_value.ignore_analysis_pattern.return_value = True
    mock_dependencies_scan.return_value.process.return_value = "scanned_dependencies"
    mock_dependencies_scan.return_value.deserializator.return_value = ["dep"]
    mock_set_input_core.return_value.set_input_core.return_value = "core_input"

    tool_remote = MagicMock(spec=DevopsPlatformGateway)
    tool_remote.get_variable.return_value = "main"
    remote_config_source_gateway = MagicMock(spec=DevopsPlatformGateway)
    tool_sbom = MagicMock(spec=SbomManagerGateway)
    tool_sbom.get_components.return_value = [Mock()]

    tool_license_manager = MagicMock()
    tool_license_manager.upload_sbom.return_value = "task_abc123"

    config_tool = {
        "SBOM_MANAGER": {"ENABLED": True, "BRANCH_FILTER": ["main"]},
        "ENGINE_DEPENDENCIES": {"TOOL": "tool"},
        "LICENSE_ANALYZER": {
            "TOOL": "dep_track",
            "dep_track": {
                "API_KEY_SECRET_KEY": "api_key_secret",
                "HOST": "http://host",
                "EXPORT_TASK_ID": True,
                "TASK_ID_VARIABLE_NAME": "DT_TASK_ID",
            },
        },
    }
    dict_args = {"remote_config_repo": "repo", "folder_path": "path", "remote_config_branch": "", "use_license_analyzer": "true"}

    secret_tool = MagicMock()
    secret_tool.get_secret.return_value = "valid_token"

    init_engine_dependencies(
        Mock(), tool_remote, remote_config_source_gateway, Mock(), dict_args,
        secret_tool, config_tool, tool_sbom, tool_license_manager
    )

    tool_license_manager.upload_sbom.assert_called_once()
    mock_logger.info.assert_any_call("SBOM uploaded to license analyzer with task ID: task_abc123")
    tool_remote.set_variable.assert_called_once_with("DT_TASK_ID", "task_abc123")


@patch('devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.entry_points.entry_point_tool.HandleRemoteConfigPatterns')
@patch('devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.entry_points.entry_point_tool.SetInputCore')
@patch('devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.entry_points.entry_point_tool.DependenciesScan')
@patch('devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.entry_points.entry_point_tool.os.path.exists')
@patch('devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.entry_points.entry_point_tool.logger')
def test_init_engine_dependencies_license_upload_without_task_id_does_not_export(mock_logger, mock_exists, mock_dependencies_scan, mock_set_input_core, mock_handle_remote_config_patterns):
    mock_exists.return_value = True
    mock_handle_remote_config_patterns.return_value.skip_from_exclusion.return_value = False
    mock_handle_remote_config_patterns.return_value.ignore_analysis_pattern.return_value = True
    mock_dependencies_scan.return_value.process.return_value = "scanned_dependencies"
    mock_dependencies_scan.return_value.deserializator.return_value = ["dep"]
    mock_set_input_core.return_value.set_input_core.return_value = "core_input"

    tool_remote = MagicMock(spec=DevopsPlatformGateway)
    tool_remote.get_variable.return_value = "main"
    remote_config_source_gateway = MagicMock(spec=DevopsPlatformGateway)
    tool_sbom = MagicMock(spec=SbomManagerGateway)
    tool_sbom.get_components.return_value = [Mock()]

    tool_license_manager = MagicMock()
    tool_license_manager.upload_sbom.return_value = None

    config_tool = {
        "SBOM_MANAGER": {"ENABLED": True, "BRANCH_FILTER": ["main"]},
        "ENGINE_DEPENDENCIES": {"TOOL": "tool"},
        "LICENSE_ANALYZER": {
            "TOOL": "dep_track",
            "dep_track": {
                "API_KEY_SECRET_KEY": "api_key_secret",
                "HOST": "http://host",
                "EXPORT_TASK_ID": True,
                "TASK_ID_VARIABLE_NAME": "DT_TASK_ID",
            },
        },
    }
    dict_args = {"remote_config_repo": "repo", "folder_path": "path", "remote_config_branch": "", "use_license_analyzer": "true"}

    secret_tool = MagicMock()
    secret_tool.get.return_value = "valid_token"

    init_engine_dependencies(
        Mock(), tool_remote, remote_config_source_gateway, Mock(), dict_args,
        secret_tool, config_tool, tool_sbom, tool_license_manager
    )

    tool_license_manager.upload_sbom.assert_called_once()
    tool_remote.set_variable.assert_not_called()
    mock_logger.warning.assert_any_call("SBOM upload to license analyzer failed or returned empty task ID.")


