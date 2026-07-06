from devsecops_engine_tools.engine_sca.engine_license.src.domain.usecases.license_policy import (
    build_policy_from_remote_config,
    classify_package,
    get_value,
    looks_like_spdx_id,
    validate_action,
    _DEFAULT_SEVERITY_BY_ACTION,
)


def _policy(**overrides):
    """Helper: build a default-flavoured policy and apply overrides."""
    base = {
        "fail": ["AGPL-*", "SSPL-*"],
        "warn": ["BUSL-*", "EPL-*", "LGPL-3.0*"],
        "synonyms": {},
        "unlicensed_action": "ignore",
        "unknown_action": "ignore",
        "severity_mapping": dict(_DEFAULT_SEVERITY_BY_ACTION),
    }
    base.update(overrides)
    return base


def test_get_value_returns_first_non_none():
    obj = {"a": None, "B": "value", "c": "other"}
    assert get_value(obj, "a", "B", "c") == "value"
    assert get_value({}, "x", default="d") == "d"
    assert get_value(None, "x", default="d") == "d"


def test_validate_action_clamps_to_known_set():
    assert validate_action("FAIL", "ignore") == "fail"
    assert validate_action(" Warn ", "ignore") == "warn"
    assert validate_action("bogus", "ignore") == "ignore"


def test_looks_like_spdx_id():
    assert looks_like_spdx_id("MIT")
    assert looks_like_spdx_id("Apache-2.0")
    assert looks_like_spdx_id("GPL-3.0+")
    assert not looks_like_spdx_id("")
    assert not looks_like_spdx_id("MIT License")
    assert not looks_like_spdx_id("a" * 80)

def test_build_policy_returns_none_when_remote_config_missing():
    assert build_policy_from_remote_config(None) is None
    assert build_policy_from_remote_config({}) is None
    assert build_policy_from_remote_config({"LICENSE": {}}) is None


def test_build_policy_normalises_lists_and_actions():
    raw = {
        "LICENSE": {
            "LICENSE_POLICY": {
                "fail": ["AGPL-*"],
                "warn": ["BUSL-*"],
                "synonyms": {"BSD": "BSD-3-Clause"},
                "unlicensed_action": "WARN",
                "unknown_action": "Bogus",
            }
        }
    }
    policy = build_policy_from_remote_config(raw)
    assert policy["fail"] == ["AGPL-*"]
    assert policy["warn"] == ["BUSL-*"]
    assert policy["synonyms"] == {"BSD": "BSD-3-Clause"}
    assert policy["unlicensed_action"] == "warn"
    assert policy["unknown_action"] == "ignore"


def test_build_policy_handles_non_list_fail_warn():
    raw = {"LICENSE": {"LICENSE_POLICY": {"fail": "not-a-list", "warn": None}}}
    policy = build_policy_from_remote_config(raw)
    assert policy["fail"] == []
    assert policy["warn"] == []


def test_build_policy_default_severity_mapping():
    raw = {"LICENSE": {"LICENSE_POLICY": {"fail": [], "warn": []}}}
    policy = build_policy_from_remote_config(raw)
    assert policy["severity_mapping"] == _DEFAULT_SEVERITY_BY_ACTION


def test_build_policy_severity_mapping_override():
    raw = {
        "LICENSE": {
            "LICENSE_POLICY": {
                "fail": ["AGPL-*"],
                "warn": [],
                "severity_mapping": {"fail": "high"},
            }
        }
    }
    policy = build_policy_from_remote_config(raw)
    assert policy["severity_mapping"]["fail"] == "high"
    assert policy["severity_mapping"]["warn"] == _DEFAULT_SEVERITY_BY_ACTION["warn"]

    result = classify_package([{"id": "AGPL-3.0"}], policy)
    assert result["policy_applied"] == "fail"
    assert result["severity"] == "high"

def test_classify_package_compliant_spdx():
    result = classify_package([{"id": "MIT"}], _policy())
    assert result["policy_applied"] == "ok"
    assert result["label"] == "MIT"
    assert result["licenses"] == ["MIT"]
    assert result["pattern_matched"] is None
    assert result["severity"] == "info"


def test_classify_package_fail_pattern():
    result = classify_package([{"id": "AGPL-3.0"}], _policy())
    assert result["policy_applied"] == "fail"
    assert result["pattern_matched"] == "AGPL-*"
    assert "AGPL-*" in result["reason"]
    assert result["severity"] == "critical"


def test_classify_package_warn_pattern():
    result = classify_package([{"id": "BUSL-1.1"}], _policy())
    assert result["policy_applied"] == "warn"
    assert result["pattern_matched"] == "BUSL-*"
    assert result["severity"] == "medium"


def test_classify_package_dual_license_highest_risk_wins():
    result = classify_package(
        [{"id": "AGPL-3.0"}, {"id": "MIT"}], _policy()
    )
    assert result["policy_applied"] == "fail"
    assert sorted(result["licenses"]) == ["AGPL-3.0", "MIT"]


def test_classify_package_dual_warn_and_fail_picks_fail():
    result = classify_package(
        [{"id": "AGPL-3.0"}, {"id": "BUSL-1.1"}], _policy()
    )
    assert result["policy_applied"] == "fail"


def test_classify_package_synonyms_resolved():
    policy = _policy(synonyms={"BSD": "BSD-3-Clause"})
    result = classify_package([{"id": "BSD"}], policy)
    assert result["policy_applied"] == "ok"
    assert result["label"] == "BSD-3-Clause"


def test_classify_package_unlicensed_ignore_severity_info():
    result = classify_package([], _policy(unlicensed_action="ignore"))
    assert result["policy_applied"] == "unlicensed"
    assert result["label"] == "UNLICENSED"
    assert result["severity"] == "info"


def test_classify_package_unlicensed_warn_severity_medium():
    result = classify_package([], _policy(unlicensed_action="warn"))
    assert result["policy_applied"] == "unlicensed"
    assert result["label"] == "UNLICENSED"
    assert result["severity"] == "medium"


def test_classify_package_unknown_label_ignore_severity_info():
    result = classify_package(
        [{"name": "Custom Proprietary License"}],
        _policy(unknown_action="ignore"),
    )
    assert result["policy_applied"] == "unknown"
    assert result["severity"] == "info"


def test_classify_package_unknown_label_fail_severity_critical():
    result = classify_package(
        [{"name": "Custom Proprietary License"}],
        _policy(unknown_action="fail"),
    )
    assert result["policy_applied"] == "unknown"
    assert result["severity"] == "critical"


def test_classify_package_with_none_policy():
    result = classify_package([{"id": "MIT"}], None)
    assert result["policy_applied"] == "unknown"
    assert result["label"] == "UNKNOWN"
    assert result["severity"] == "info"


def test_severity_by_action_defaults():
    assert _DEFAULT_SEVERITY_BY_ACTION["fail"] == "critical"
    assert _DEFAULT_SEVERITY_BY_ACTION["warn"] == "medium"
    assert _DEFAULT_SEVERITY_BY_ACTION["ok"] == "info"
