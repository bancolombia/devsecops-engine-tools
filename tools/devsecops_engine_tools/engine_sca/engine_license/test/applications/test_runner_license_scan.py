from unittest.mock import MagicMock, patch

import pytest
import runpy

from devsecops_engine_tools.engine_sca.engine_license.src.applications.runner_license_scan import (
    runner_engine_license,
)


def _make_devops_gateway(pipeline_name="svc"):
    gw = MagicMock()
    gw.get_variable.side_effect = lambda name: {
        "pipeline_name": pipeline_name,
    }.get(name, "")
    return gw


def test_runner_engine_license_grant_returns_findings_input_core_and_components():
    with patch(
        "devsecops_engine_tools.engine_sca.engine_license.src.applications.runner_license_scan.init_engine_license"
    ) as mock_init, patch(
        "devsecops_engine_tools.engine_sca.engine_license.src.applications.runner_license_scan.GrantScan"
    ):
        mock_init.return_value = ("/abs/svc_LICENSE.json", ["c1"])

        config_tool = {"ENGINE_LICENSE": {"TOOL": "GRANT"}}
        devops_gw = _make_devops_gateway()

        findings, input_core, sbom_components, tool_gw = runner_engine_license(
            {"remote_config_repo": "r", "remote_config_branch": ""},
            config_tool,
            None,
            devops_gw,
            None,
            None,
        )

        mock_init.assert_called_once()

        assert findings == []
        assert sbom_components == ["c1"]
        assert tool_gw is not None

        assert input_core.path_file_results == "/abs/svc_LICENSE.json"
        assert input_core.totalized_exclusions == []
        assert input_core.scope_pipeline == "svc"
        assert input_core.scope_service == "svc"
        assert input_core.stage_pipeline == "Build"
        assert input_core.custom_message_break_build == "License scan completed"

        assert input_core.threshold_defined is not None
        assert input_core.threshold_defined.vulnerability.critical is None
        assert input_core.threshold_defined.compliance.critical is None


def test_runner_engine_license_propagates_none_path():
    """When init_engine_license fails, runner still returns a usable InputCore."""
    with patch(
        "devsecops_engine_tools.engine_sca.engine_license.src.applications.runner_license_scan.init_engine_license"
    ) as mock_init, patch(
        "devsecops_engine_tools.engine_sca.engine_license.src.applications.runner_license_scan.GrantScan"
    ):
        mock_init.return_value = (None, None)
        config_tool = {"ENGINE_LICENSE": {"TOOL": "GRANT"}}
        devops_gw = _make_devops_gateway()

        findings, input_core, sbom_components, tool_gw = runner_engine_license(
            {"remote_config_repo": "r", "remote_config_branch": ""},
            config_tool,
            None,
            devops_gw,
            None,
            None,
        )

        assert findings == []
        assert sbom_components is None
        assert input_core.path_file_results is None
        assert input_core.scope_pipeline == "svc"


def test_runner_engine_license_unknown_tool_raises():
    config_tool = {"ENGINE_LICENSE": {"TOOL": "UNKNOWN"}}
    with pytest.raises(Exception, match="Error SCAN engine license"):
        runner_engine_license({}, config_tool, None, None, None, None)


def test_runner_license_main_block():
    with pytest.raises((TypeError, Exception)):
        runpy.run_module(
            "devsecops_engine_tools.engine_sca.engine_license.src.applications.runner_license_scan",
            run_name="__main__",
            alter_sys=True,
        )
