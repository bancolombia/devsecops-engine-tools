import json
import os
from unittest.mock import patch

import pytest

from devsecops_engine_tools.engine_sca.engine_license.src.domain.usecases.build_license_report import (
    BuildLicenseReport,
)


def _remote_config():
    return {
        "GRANT": {
            "LICENSE_POLICY": {
                "fail": ["AGPL-*"],
                "warn": ["BUSL-*"],
                "synonyms": {},
                "unlicensed_action": "warn",
                "unknown_action": "ignore",
            }
        }
    }


def _grant_payload(packages, source_ref="path/to/my-app_sbom.json"):
    return {
        "run": {
            "targets": [
                {
                    "source": {"ref": source_ref},
                    "evaluation": {
                        "findings": {"packages": packages},
                    },
                }
            ]
        }
    }


def _write_grant(tmp_path, payload):
    path = tmp_path / "grant_report.json"
    path.write_text(json.dumps(payload))
    return str(path)


# ---------------------------------------------------------------- happy path


def test_process_writes_license_json_with_mixed_classifications(tmp_path):
    packages = [
        {"name": "lodash", "version": "4.17.21", "licenses": [{"id": "MIT"}]},
        {"name": "ngrx", "version": "1.0.0", "licenses": [{"id": "AGPL-3.0"}]},
        {"name": "biz-lib", "version": "2.0.0", "licenses": [{"id": "BUSL-1.1"}]},
        {"name": "no-lic-pkg", "version": "0.1.0", "licenses": []},
        {
            "name": "weird-pkg",
            "version": "0.0.1",
            "licenses": [{"name": "Custom Proprietary License"}],
        },
        {"name": "my-app", "version": "1.0.0", "licenses": [{"id": "MIT"}]},
    ]
    report_path = _write_grant(tmp_path, _grant_payload(packages))

    use_case = BuildLicenseReport(output_dir=str(tmp_path))
    out_path = use_case.process(report_path, _remote_config(), "svc")

    assert out_path is not None
    assert os.path.exists(out_path)
    assert out_path.endswith("svc_LICENSE.json")

    with open(out_path) as fh:
        report = json.load(fh)

    md = report["metadata"]
    assert md["pipeline_name"] == "svc"
    assert md["tool"] == "GRANT"
    assert md["policy_used"] == _remote_config()["GRANT"]["LICENSE_POLICY"]
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


def test_process_dual_license_ok_dominates(tmp_path):
    packages = [
        {
            "name": "dual-pkg",
            "version": "1.0",
            "licenses": [{"id": "AGPL-3.0"}, {"id": "MIT"}],
        }
    ]
    report_path = _write_grant(tmp_path, _grant_payload(packages))

    out = BuildLicenseReport(output_dir=str(tmp_path)).process(
        report_path, _remote_config(), "svc"
    )

    with open(out) as fh:
        report = json.load(fh)
    dep = report["dependencies"][0]
    assert dep["policy_applied"] == "ok"
    assert sorted(dep["licenses"]) == ["AGPL-3.0", "MIT"]


def test_process_metadata_policy_used_is_deep_copy(tmp_path):
    """Mutating the returned report must not affect the source remote_config."""
    config = _remote_config()
    report_path = _write_grant(
        tmp_path,
        _grant_payload(
            [{"name": "x", "version": "1", "licenses": [{"id": "MIT"}]}]
        ),
    )
    out = BuildLicenseReport(output_dir=str(tmp_path)).process(
        report_path, config, "svc"
    )

    with open(out) as fh:
        report = json.load(fh)
    report["metadata"]["policy_used"]["fail"].append("MUTATED")
    assert config["GRANT"]["LICENSE_POLICY"]["fail"] == ["AGPL-*"]

def test_process_returns_none_when_remote_config_missing(tmp_path):
    report_path = _write_grant(tmp_path, _grant_payload([]))
    assert (
        BuildLicenseReport(output_dir=str(tmp_path)).process(
            report_path, {}, "svc"
        )
        is None
    )


def test_process_returns_none_when_grant_report_missing(tmp_path):
    out = BuildLicenseReport(output_dir=str(tmp_path)).process(
        str(tmp_path / "does_not_exist.json"), _remote_config(), "svc"
    )
    assert out is None


def test_process_returns_none_when_grant_report_path_is_empty(tmp_path):
    out = BuildLicenseReport(output_dir=str(tmp_path)).process(
        "", _remote_config(), "svc"
    )
    assert out is None


def test_process_returns_none_when_grant_report_invalid_json(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("not-json{{{")
    out = BuildLicenseReport(output_dir=str(tmp_path)).process(
        str(bad), _remote_config(), "svc"
    )
    assert out is None


def test_process_handles_empty_targets(tmp_path):
    report_path = _write_grant(tmp_path, {"run": {"targets": []}})
    out = BuildLicenseReport(output_dir=str(tmp_path)).process(
        report_path, _remote_config(), "svc"
    )
    with open(out) as fh:
        report = json.load(fh)
    assert report["dependencies"] == []
    assert report["metadata"]["summary"]["total_dependencies"] == 0


def test_process_falls_back_to_results_key(tmp_path):
    payload = {
        "results": [
            {
                "source": {"ref": "x.json"},
                "evaluation": {
                    "findings": {
                        "packages": [
                            {"name": "p", "version": "1", "licenses": [{"id": "MIT"}]}
                        ]
                    }
                },
            }
        ]
    }
    report_path = _write_grant(tmp_path, payload)
    out = BuildLicenseReport(output_dir=str(tmp_path)).process(
        report_path, _remote_config(), "svc"
    )
    with open(out) as fh:
        report = json.load(fh)
    assert len(report["dependencies"]) == 1


def test_process_returns_none_when_write_fails(tmp_path):
    """If file writing fails, process returns None."""
    report_path = _write_grant(
        tmp_path,
        _grant_payload(
            [{"name": "x", "version": "1", "licenses": [{"id": "MIT"}]}]
        ),
    )
    use_case = BuildLicenseReport(output_dir=str(tmp_path))
    with patch(
        "devsecops_engine_tools.engine_sca.engine_license.src.domain.usecases.build_license_report.open",
        side_effect=OSError("disk full"),
    ):
        pass

    with patch.object(use_case, "_write_report", return_value=None):
        out = use_case.process(report_path, _remote_config(), "svc")
    assert out is None


def test_default_output_dir_is_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    report_path = _write_grant(
        tmp_path,
        _grant_payload(
            [{"name": "x", "version": "1", "licenses": [{"id": "MIT"}]}]
        ),
    )
    out = BuildLicenseReport().process(report_path, _remote_config(), "svc")
    assert out is not None
    assert os.path.dirname(out) == str(tmp_path)
