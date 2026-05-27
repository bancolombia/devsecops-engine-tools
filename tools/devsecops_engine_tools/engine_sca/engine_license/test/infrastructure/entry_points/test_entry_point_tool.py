from unittest.mock import MagicMock, patch

from devsecops_engine_tools.engine_sca.engine_license.src.infrastructure.entry_points.entry_point_tool import (
    init_engine_license,
)


def _make_devops_gateway(remote_cfg, pipeline_name="svc"):
    gw = MagicMock()
    gw.get_remote_config.return_value = remote_cfg
    gw.get_variable.side_effect = lambda name: {
        "pipeline_name": pipeline_name,
        "branch_tag": "main",
    }.get(name, "")
    return gw


def _config_tool():
    return {
        "ENGINE_LICENSE": {"TOOL": "GRANT"},
        "SBOM_MANAGER": {"ENABLED": True},
    }


def _remote_config():
    return {
        "GRANT": {
            "LICENSE_POLICY": {
                "fail": [],
                "warn": [],
                "synonyms": {},
                "unlicensed_action": "ignore",
                "unknown_action": "ignore",
            }
        }
    }

@patch(
    "devsecops_engine_tools.engine_sca.engine_license.src.infrastructure.entry_points.entry_point_tool.BuildLicenseReport"
)
@patch(
    "devsecops_engine_tools.engine_sca.engine_license.src.infrastructure.entry_points.entry_point_tool.os.path.exists"
)
def test_init_engine_license_happy_path(mock_exists, mock_builder):
    mock_exists.return_value = True
    mock_builder.return_value.process.return_value = "/abs/svc_LICENSE.json"

    devops_gw = _make_devops_gateway(_remote_config())
    remote_gw = _make_devops_gateway(_remote_config())

    tool_run = MagicMock()
    tool_run.run_tool_license_sca.return_value = "svc_grant.json"

    tool_sbom = MagicMock()
    tool_sbom.get_components.return_value = ["c1", "c2"]

    license_path, sbom_components = init_engine_license(
        tool_run,
        devops_gw,
        remote_gw,
        {"remote_config_repo": "r", "remote_config_branch": ""},
        None,
        _config_tool(),
        tool_sbom,
    )

    assert license_path == "/abs/svc_LICENSE.json"
    assert sbom_components == ["c1", "c2"]

    tool_sbom.get_components.assert_called_once()
    tool_run.run_tool_license_sca.assert_called_once()
    args, _ = tool_run.run_tool_license_sca.call_args
    assert args[5] == "svc_SBOM.json"  # sbom_path
    assert args[7] is None  # image_to_scan

    mock_builder.return_value.process.assert_called_once_with(
        "svc_grant.json", _remote_config(), "svc"
    )


@patch(
    "devsecops_engine_tools.engine_sca.engine_license.src.infrastructure.entry_points.entry_point_tool.os.path.exists",
    return_value=False,
)
def test_init_engine_license_returns_none_when_to_scan_missing(mock_exists):
    devops_gw = _make_devops_gateway(_remote_config())
    remote_gw = _make_devops_gateway(_remote_config())
    tool_run = MagicMock()
    tool_sbom = MagicMock()

    license_path, sbom_components = init_engine_license(
        tool_run,
        devops_gw,
        remote_gw,
        {
            "remote_config_repo": "r",
            "remote_config_branch": "",
            "folder_path": "/missing/path",
        },
        None,
        _config_tool(),
        tool_sbom,
    )

    assert license_path is None
    assert sbom_components is None
    tool_sbom.get_components.assert_not_called()


@patch(
    "devsecops_engine_tools.engine_sca.engine_license.src.infrastructure.entry_points.entry_point_tool.os.path.exists"
)
def test_init_engine_license_returns_none_when_sbom_missing_after_generation(
    mock_exists,
):
    mock_exists.side_effect = [True, False]
    devops_gw = _make_devops_gateway(_remote_config())
    remote_gw = _make_devops_gateway(_remote_config())
    tool_run = MagicMock()
    tool_sbom = MagicMock()
    tool_sbom.get_components.return_value = ["c"]

    license_path, sbom_components = init_engine_license(
        tool_run,
        devops_gw,
        remote_gw,
        {"remote_config_repo": "r", "remote_config_branch": ""},
        None,
        _config_tool(),
        tool_sbom,
    )

    assert license_path is None
    assert sbom_components == ["c"]
    tool_run.run_tool_license_sca.assert_not_called()


@patch(
    "devsecops_engine_tools.engine_sca.engine_license.src.infrastructure.entry_points.entry_point_tool.os.path.exists",
    return_value=True,
)
def test_init_engine_license_returns_none_when_tool_sbom_missing(mock_exists):
    devops_gw = _make_devops_gateway(_remote_config())
    remote_gw = _make_devops_gateway(_remote_config())
    tool_run = MagicMock()

    license_path, sbom_components = init_engine_license(
        tool_run,
        devops_gw,
        remote_gw,
        {"remote_config_repo": "r", "remote_config_branch": ""},
        None,
        _config_tool(),
        None,
    )

    assert license_path is None
    assert sbom_components is None
    tool_run.run_tool_license_sca.assert_not_called()


@patch(
    "devsecops_engine_tools.engine_sca.engine_license.src.infrastructure.entry_points.entry_point_tool.os.path.exists",
    return_value=True,
)
def test_init_engine_license_returns_none_when_grant_fails(mock_exists):
    devops_gw = _make_devops_gateway(_remote_config())
    remote_gw = _make_devops_gateway(_remote_config())
    tool_run = MagicMock()
    tool_run.run_tool_license_sca.return_value = None
    tool_sbom = MagicMock()
    tool_sbom.get_components.return_value = ["c"]

    license_path, sbom_components = init_engine_license(
        tool_run,
        devops_gw,
        remote_gw,
        {"remote_config_repo": "r", "remote_config_branch": ""},
        None,
        _config_tool(),
        tool_sbom,
    )

    assert license_path is None
    assert sbom_components == ["c"]


@patch(
    "devsecops_engine_tools.engine_sca.engine_license.src.infrastructure.entry_points.entry_point_tool.BuildLicenseReport"
)
@patch(
    "devsecops_engine_tools.engine_sca.engine_license.src.infrastructure.entry_points.entry_point_tool.os.path.exists",
    return_value=True,
)
def test_init_engine_license_returns_none_when_build_report_fails(
    mock_exists, mock_builder
):
    mock_builder.return_value.process.return_value = None
    devops_gw = _make_devops_gateway(_remote_config())
    remote_gw = _make_devops_gateway(_remote_config())
    tool_run = MagicMock()
    tool_run.run_tool_license_sca.return_value = "grant.json"
    tool_sbom = MagicMock()
    tool_sbom.get_components.return_value = ["c"]

    license_path, sbom_components = init_engine_license(
        tool_run,
        devops_gw,
        remote_gw,
        {"remote_config_repo": "r", "remote_config_branch": ""},
        None,
        _config_tool(),
        tool_sbom,
    )
    assert license_path is None
    assert sbom_components == ["c"]
