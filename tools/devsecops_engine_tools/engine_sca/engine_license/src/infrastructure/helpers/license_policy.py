"""Pure license classification helpers used by the engine_license module.

Functions in this module are stateless and do not perform I/O. They are
shared by the LICENSE.json builder and any other consumer that needs to
classify SBOM packages against a remote_config policy.

Policy buckets exposed via ``classify_package`` map 1:1 to the summary
buckets in the LICENSE.json artifact: ``ok``, ``fail``, ``warn``,
``unlicensed`` and ``unknown``.
"""

import fnmatch
import re

from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()

TOOL = "LICENSE"

_DEFAULT_SEVERITY_BY_ACTION = {
    "fail": "critical",
    "warn": "medium",
    "ok": "info",
    "ignore": "info",
}

__DEFAULT_VALID_ACTIONS = {"fail", "warn", "info", "ignore"}


def get_value(obj, *keys, default=None):
    """Return the first non-None value among the given key variants."""
    if not isinstance(obj, dict):
        return default
    for key in keys:
        if key in obj and obj[key] is not None:
            return obj[key]
    return default


def validate_action(value, default):
    """Return value (lowercased) if it is a valid action, else default."""
    v = str(value).lower().strip()
    return v if v in __DEFAULT_VALID_ACTIONS else default


def looks_like_spdx_id(label):
    """Heuristic: SPDX ids are short, no spaces, alphanumeric + a few symbols."""
    if not label or len(label) > 60:
        return False
    if " " in label:
        return False
    return bool(re.match(r"^[A-Za-z0-9.\-+]+$", label))


def build_policy_from_remote_config(remote_config):
    """Build the policy dict from remote_config LICENSE_POLICY section.

    Returns None (and logs error) if the configuration is absent.
    """
    if not (remote_config and isinstance(remote_config, dict)):
        logger.error("No remote_config provided: LICENSE_POLICY is required.")
        return None

    override = (remote_config.get(TOOL) or {}).get("LICENSE_POLICY")
    if not isinstance(override, dict):
        logger.error(
            "remote_config missing LICENSE_POLICY configuration: cannot classify licenses."
        )
        return None

    fail_raw = override.get("fail", [])
    warn_raw = override.get("warn", [])

    fail_list = [str(p) for p in fail_raw] if isinstance(fail_raw, list) else []
    warn_list = [str(p) for p in warn_raw] if isinstance(warn_raw, list) else []

    synonyms_raw = override.get("synonyms", {})
    synonyms = {
        str(k): str(v)
        for k, v in (synonyms_raw.items() if isinstance(synonyms_raw, dict) else [])
    }

    severity_mapping = dict(_DEFAULT_SEVERITY_BY_ACTION)
    severity_mapping_raw = override.get("severity_mapping", {})
    if isinstance(severity_mapping_raw, dict):
        severity_mapping.update(
            {str(k): str(v) for k, v in severity_mapping_raw.items()}
        )

    return {
        "fail": fail_list,
        "warn": warn_list,
        "synonyms": synonyms,
        "unlicensed_action": validate_action(
            override.get("unlicensed_action", "ignore"), "ignore"
        ),
        "unknown_action": validate_action(
            override.get("unknown_action", "ignore"), "ignore"
        ),
        "severity_mapping": severity_mapping,
    }


def _classify_label(normalized_label, policy):
    """Classify a single normalized license label.

    Returns a dict with: bucket ∈ {fail, warn, ok, unknown}, reason,
    pattern_matched (str|None).
    """
    label = (normalized_label or "").strip()
    label_lc = label.lower()

    for pattern in policy["fail"]:
        if fnmatch.fnmatchcase(label_lc, pattern.lower()):
            return {
                "bucket": "fail",
                "reason": f"matches FAIL pattern '{pattern}'",
                "pattern_matched": pattern,
            }

    for pattern in policy["warn"]:
        if fnmatch.fnmatchcase(label_lc, pattern.lower()):
            return {
                "bucket": "warn",
                "reason": f"matches WARN pattern '{pattern}'",
                "pattern_matched": pattern,
            }

    if looks_like_spdx_id(label):
        return {
            "bucket": "ok",
            "reason": "compliant SPDX license",
            "pattern_matched": None,
        }

    return {
        "bucket": "unknown",
        "reason": "non-SPDX license label",
        "pattern_matched": None,
    }


def _extract_license_id(license_entry):
    """Best-effort extraction of a license identifier from a CycloneDX SBOM entry."""
    return (
        get_value(
            license_entry,
            "id", "Id", "ID",
            "spdxExpression", "SpdxExpression",
            "name", "Name",
            default="",
        )
        or ""
    )


def classify_package(licenses, policy):
    """Classify all licenses on a single package against the policy.

    Highest-risk-wins semantics: if ANY license on the package matches a
    ``fail`` pattern, the package is classified as ``fail``. Otherwise, if
    any matches ``warn``, the package is ``warn``. Only when all licenses are
    compliant (or a single ok is found with no risky siblings) the package is
    ``ok``.

    Args:
        licenses: list of license entries (dicts) from the CycloneDX SBOM.
            May be empty, in which case the package is considered unlicensed.
        policy: policy dict produced by ``build_policy_from_remote_config``.

    Returns:
        dict with keys:
            - policy_applied: one of {ok, fail, warn, unlicensed, unknown}
            - label: normalized license label that was applied (or
              "UNLICENSED"/"UNKNOWN" sentinels)
            - licenses: list[str] of all normalized license labels detected
            - reason: human-readable explanation
            - pattern_matched: pattern from policy that matched, or None
            - severity: effective severity tier for this entry
    """
    if policy is None:
        return {
            "policy_applied": "unknown",
            "label": "UNKNOWN",
            "licenses": [],
            "reason": "no policy available",
            "pattern_matched": None,
            "severity": _DEFAULT_SEVERITY_BY_ACTION["ignore"],
        }

    if not licenses:
        action = policy["unlicensed_action"]
        return {
            "policy_applied": "unlicensed",
            "label": "UNLICENSED",
            "licenses": [],
            "reason": "no license detected",
            "pattern_matched": None,
            "severity": policy["severity_mapping"].get(action, "info"),
        }

    normalized_labels = []
    classified = []
    for lic in licenses:
        raw_id = _extract_license_id(lic)
        normalized = (
            policy["synonyms"].get(raw_id, raw_id).strip() or "UNKNOWN"
        )
        normalized_labels.append(normalized)
        classified.append((normalized, _classify_label(normalized, policy)))

    # Highest risk wins: fail > warn > unknown > ok
    rank = {"fail": 0, "warn": 1, "unknown": 2, "ok": 3}

    def _key(item):
        return rank.get(item[1]["bucket"], 99)

    classified.sort(key=_key)
    label, result = classified[0]
    bucket = result["bucket"]

    if bucket == "unknown":
        severity = policy["severity_mapping"].get(policy["unknown_action"], "info")
    elif bucket == "ok":
        severity = policy["severity_mapping"].get("ok", "info")
    else:
        severity = policy["severity_mapping"].get(bucket, "info")

    return {
        "policy_applied": bucket,
        "label": label,
        "licenses": normalized_labels,
        "reason": result["reason"],
        "pattern_matched": result["pattern_matched"],
        "severity": severity,
    }
