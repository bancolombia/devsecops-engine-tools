from dataclasses import asdict

from devsecops_engine_tools.engine_sca.engine_license.src.domain.model.context_license import (
    ContextLicense,
)


def test_context_license_instantiation_and_asdict():
    ctx = ContextLicense(
        name="lodash",
        version="4.17.21",
        licenses=["MIT"],
        policy_applied="ok",
        policy_reason="Allowed by default",
        policy_pattern_matched="",
        severity="low",
    )
    d = asdict(ctx)
    assert d["name"] == "lodash"
    assert d["licenses"] == ["MIT"]
    assert d["severity"] == "low"
    assert d["priority"] is None


def test_context_license_with_priority():
    ctx = ContextLicense(
        name="ngrx",
        version="1.0.0",
        licenses=["AGPL-3.0"],
        policy_applied="fail",
        policy_reason="Matched AGPL-*",
        policy_pattern_matched="AGPL-*",
        severity="critical",
        priority="very critical",
    )
    assert ctx.priority == "very critical"
