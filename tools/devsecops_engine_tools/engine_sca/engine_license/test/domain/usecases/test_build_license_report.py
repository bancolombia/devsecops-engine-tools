import json
import os
from unittest.mock import patch

import pytest

from devsecops_engine_tools.engine_sca.engine_license.src.domain.usecases.build_license_report import (
    BuildLicenseReport,
)


def _remote_config():
    return {
        "LICENSE": {
            "LICENSE_POLICY": {
                "fail": ["AGPL-*"],
                "warn": ["BUSL-*"],
                "synonyms": {},
                "unlicensed_action": "warn",
                "unknown_action": "ignore",
            }
        }
    }


def _sbom_payload(components):
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": components,
    }


def _write_sbom(tmp_path, payload):
    path = tmp_path / "sbom.json"
    path.write_text(json.dumps(payload))
    return str(path)


def test_process_writes_license_json_with_mixed_classifications(tmp_path):
    components = [
        {"name": "lodash", "version": "4.17.21", "licenses": [{"license": {"id": "MIT"}}]},
        {"name": "ngrx", "version": "1.0.0", "licenses": [{"license": {"id": "AGPL-3.0"}}]},
        {"name": "biz-lib", "version": "2.0.0", "licenses": [{"license": {"id": "BUSL-1.1"}}]},
        {"name": "no-lic-pkg", "version": "0.1.0", "licenses": []},
        {"name": "weird-pkg", "version": "0.0.1", "licenses": [{"license": {"name": "Custom Proprietary License"}}]},
    ]
    sbom_path = _write_sbom(tmp_path, _sbom_payload(components))

    use_case = BuildLicenseReport(output_dir=str(tmp_path))
    out_path = use_case.process(sbom_path, _remote_config(), "svc")

    assert out_path is not None
    assert os.path.exists(out_path)
    assert out_path.endswith("svc_LICENSE.json")

    with open(out_path) as fh:
        report = json.load(fh)

    md = report["metadata"]
    assert md["pipeline_name"] == "svc"
    assert md["tool"] == "CDXGEN"
    assert md["policy_used"] == _remote_config()["LICENSE"]["LICENSE_POLICY"]
    assert md["summary"]["total_dependencies"] == 5
    assert md["summary"]["ok"] == 1
    assert md["summary"]["fail"] == 1
    assert md["summary"]["warn"] == 1
    assert md["summary"]["unlicensed"] == 1
    assert md["summary"]["unknown"] == 1

    deps = report["dependencies"]
    assert len(deps) == 5
    names = [d["name"] for d in deps]
    assert names == ["lodash", "ngrx", "biz-lib", "no-lic-pkg", "weird-pkg"]

    ngrx = next(d for d in deps if d["name"] == "ngrx")
    assert ngrx["policy_applied"] == "fail"
    assert ngrx["policy_pattern_matched"] == "AGPL-*"
    assert "AGPL-*" in ngrx["policy_reason"]

    no_lic = next(d for d in deps if d["name"] == "no-lic-pkg")
    assert no_lic["policy_applied"] == "unlicensed"
    assert no_lic["licenses"] == []


def test_process_dual_license_highest_risk_wins(tmp_path):
    components = [
        {"name": "dual-pkg", "version": "1.0", "licenses": [{"license": {"id": "AGPL-3.0"}}, {"license": {"id": "MIT"}}]},
    ]
    sbom_path = _write_sbom(tmp_path, _sbom_payload(components))

    out = BuildLicenseReport(output_dir=str(tmp_path)).process(
        sbom_path, _remote_config(), "svc"
    )

    with open(out) as fh:
        report = json.load(fh)
    dep = report["dependencies"][0]
    assert dep["policy_applied"] == "fail"
    assert sorted(dep["licenses"]) == ["AGPL-3.0", "MIT"]


def test_process_metadata_policy_used_is_deep_copy(tmp_path):
    config = _remote_config()
    sbom_path = _write_sbom(
        tmp_path,
        _sbom_payload([{"name": "x", "version": "1", "licenses": [{"license": {"id": "MIT"}}]}]),
    )
    out = BuildLicenseReport(output_dir=str(tmp_path)).process(
        sbom_path, config, "svc"
    )

    with open(out) as fh:
        report = json.load(fh)
    report["metadata"]["policy_used"]["fail"].append("MUTATED")
    assert config["LICENSE"]["LICENSE_POLICY"]["fail"] == ["AGPL-*"]


def test_process_returns_none_when_remote_config_missing(tmp_path):
    sbom_path = _write_sbom(tmp_path, _sbom_payload([]))
    assert (
        BuildLicenseReport(output_dir=str(tmp_path)).process(
            sbom_path, {}, "svc"
        )
        is None
    )


def test_process_returns_none_when_sbom_missing(tmp_path):
    out = BuildLicenseReport(output_dir=str(tmp_path)).process(
        str(tmp_path / "does_not_exist.json"), _remote_config(), "svc"
    )
    assert out is None


def test_process_returns_none_when_sbom_path_is_empty(tmp_path):
    out = BuildLicenseReport(output_dir=str(tmp_path)).process(
        "", _remote_config(), "svc"
    )
    assert out is None


def test_process_returns_none_when_sbom_invalid_json(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("not-json{{{" )
    out = BuildLicenseReport(output_dir=str(tmp_path)).process(
        str(bad), _remote_config(), "svc"
    )
    assert out is None


def test_process_handles_empty_components(tmp_path):
    sbom_path = _write_sbom(tmp_path, {"components": []})
    out = BuildLicenseReport(output_dir=str(tmp_path)).process(
        sbom_path, _remote_config(), "svc"
    )
    with open(out) as fh:
        report = json.load(fh)
    assert report["dependencies"] == []
    assert report["metadata"]["summary"]["total_dependencies"] == 0


def test_default_output_dir_is_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    sbom_path = _write_sbom(
        tmp_path,
        _sbom_payload([{"name": "x", "version": "1", "licenses": [{"license": {"id": "MIT"}}]}]),
    )
    out = BuildLicenseReport().process(sbom_path, _remote_config(), "svc")
    assert out is not None
    assert os.path.dirname(out) == str(tmp_path)
