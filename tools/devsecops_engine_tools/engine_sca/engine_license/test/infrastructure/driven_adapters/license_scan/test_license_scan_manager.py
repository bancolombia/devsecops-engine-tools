import json

from devsecops_engine_tools.engine_sca.engine_license.src.infrastructure.driven_adapters.license_scan.license_scan_manager import (
    LicenseScanManager,
)


def test_get_license_context_from_results_success(tmp_path):
    license_data = {
        "metadata": {"pipeline_name": "svc"},
        "dependencies": [
            {"name": "lodash", "version": "4.17.21", "licenses": ["MIT"], "policy_applied": "ok", "policy_reason": "compliant", "policy_pattern_matched": None},
            {"name": "ngrx", "version": "1.0.0", "licenses": ["AGPL-3.0"], "policy_applied": "fail", "policy_reason": "matches FAIL pattern", "policy_pattern_matched": "AGPL-*"},
            {"name": "jakarta.servlet-api", "version": "6.1.0", "licenses": ["EPL-2.0", "GPL-2.0"], "policy_applied": "warn", "policy_reason": "matches WARN pattern", "policy_pattern_matched": "EPL-*"},
            {"name": "no-lic", "version": "0.1.0", "licenses": [], "policy_applied": "unlicensed", "policy_reason": "no license", "policy_pattern_matched": None},
        ],
    }
    path = tmp_path / "svc_LICENSE.json"
    path.write_text(json.dumps(license_data))

    manager = LicenseScanManager()
    result = manager.get_license_context_from_results(str(path))

    # Only fail and warn appear
    assert len(result) == 2
    assert result[0].name == "ngrx"
    assert result[0].severity == "critical"
    assert result[1].name == "jakarta.servlet-api"
    assert result[1].severity == "medium"
    assert result[0].priority is None
