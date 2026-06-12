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
    ), patch(
        "devsecops_engine_tools.engine_sca.engine_license.src.applications.runner_license_scan._build_findings_from_license_json"
    ) as mock_findings:
        mock_init.return_value = ("/abs/svc_LICENSE.json", ["c1"])
        mock_findings.return_value = []

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
        mock_findings.assert_called_once_with("/abs/svc_LICENSE.json")

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
    ), patch(
        "devsecops_engine_tools.engine_sca.engine_license.src.applications.runner_license_scan._build_findings_from_license_json"
    ) as mock_findings:
        mock_init.return_value = (None, None)
        mock_findings.return_value = []
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


def test_build_findings_from_license_json(tmp_path):
    import json
    from devsecops_engine_tools.engine_sca.engine_license.src.applications.runner_license_scan import (
        _build_findings_from_license_json,
    )
    from devsecops_engine_tools.engine_core.src.domain.model.finding import Category

    license_data = {
        "metadata": {"pipeline_name": "svc"},
        "dependencies": [
            {"name": "lodash", "version": "4.17.21", "licenses": ["MIT"], "policy_applied": "ok", "policy_reason": "compliant", "policy_pattern_matched": None, "license_matched": "MIT"},
            {"name": "ngrx", "version": "1.0.0", "licenses": ["AGPL-3.0"], "policy_applied": "fail", "policy_reason": "matches FAIL pattern 'AGPL-*'", "policy_pattern_matched": "AGPL-*", "license_matched": "AGPL-3.0"},
            {"name": "biz-lib", "version": "2.0.0", "licenses": ["Apache-2.0", "EPL-2.0"], "policy_applied": "warn", "policy_reason": "matches WARN pattern 'EPL-*'", "policy_pattern_matched": "EPL-*", "license_matched": "EPL-2.0"},
            {"name": "no-lic", "version": "0.1.0", "licenses": [], "policy_applied": "unlicensed", "policy_reason": "no license detected", "policy_pattern_matched": None, "license_matched": "UNLICENSED"},
        ],
    }
    path = tmp_path / "svc_LICENSE.json"
    path.write_text(json.dumps(license_data))

    findings = _build_findings_from_license_json(str(path))

    assert len(findings) == 2
    assert findings[0].id == "AGPL-3.0-ngrx"
    assert findings[0].severity == "critical"
    assert findings[0].where == "ngrx:1.0.0"
    assert findings[0].category == Category.COMPLIANCE
    assert findings[0].module == "engine_license"
    # Dual-license: uses EPL-2.0 (the one that matched), not Apache-2.0
    assert findings[1].id == "EPL-2.0-biz-lib"
    assert findings[1].severity == "medium"


def test_build_findings_from_license_json_none_path():
    from devsecops_engine_tools.engine_sca.engine_license.src.applications.runner_license_scan import (
        _build_findings_from_license_json,
    )
    assert _build_findings_from_license_json(None) == []
