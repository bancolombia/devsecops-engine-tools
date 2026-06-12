from unittest.mock import patch, MagicMock

from devsecops_engine_tools.engine_sca.engine_license.src.infrastructure.driven_adapters.grant_tool.grant_manager_scan import (
    GrantScan,
)


def _base_args(**overrides):
    args = {
        "remote_config_repo": "/tmp/does-not-exist",
        "remote_config_branch": "",
    }
    args.update(overrides)
    return args


def test_map_platform_linux_arm64():
    scan = GrantScan()
    assert scan._map_platform("Linux", "aarch64") == ("linux", "arm64")
    assert scan._map_platform("Darwin", "arm64") == ("darwin", "arm64")
    assert scan._map_platform("Darwin", "x86_64") == ("darwin", "amd64")


def test_map_platform_unsupported():
    scan = GrantScan()
    assert scan._map_platform("Plan9", "riscv") == (None, None)


@patch(
    "devsecops_engine_tools.engine_sca.engine_license.src.infrastructure.driven_adapters.grant_tool.grant_manager_scan.platform"
)
@patch(
    "devsecops_engine_tools.engine_sca.engine_license.src.infrastructure.driven_adapters.grant_tool.grant_manager_scan.shutil.which"
)
def test_resolve_binary_windows_rejected(mock_which, mock_platform):
    mock_which.return_value = None
    mock_platform.system.return_value = "Windows"
    mock_platform.machine.return_value = "AMD64"
    scan = GrantScan()
    assert scan._resolve_binary("0.2.5") is None


@patch(
    "devsecops_engine_tools.engine_sca.engine_license.src.infrastructure.driven_adapters.grant_tool.grant_manager_scan.shutil.which"
)
def test_resolve_binary_from_path(mock_which):
    mock_which.return_value = "/usr/local/bin/grant"
    scan = GrantScan()
    assert scan._resolve_binary("0.2.5") == "/usr/local/bin/grant"


@patch("os.path.exists")
def test_resolve_scan_target_priority(mock_exists):
    mock_exists.return_value = True
    scan = GrantScan()
    assert scan._resolve_scan_target("sbom.json", "img:tag", "/tmp/x") == "sbom.json"
    assert scan._resolve_scan_target(None, "img:tag", "/tmp/x") == "img:tag"
    assert scan._resolve_scan_target(None, None, "/tmp/x") == "/tmp/x"


@patch("os.path.exists")
def test_resolve_scan_target_none(mock_exists):
    mock_exists.return_value = False
    scan = GrantScan()
    assert scan._resolve_scan_target(None, None, "/missing") is None


@patch(
    "devsecops_engine_tools.engine_sca.engine_license.src.infrastructure.driven_adapters.grant_tool.grant_manager_scan.os.path.getsize",
    return_value=42,
)
@patch(
    "devsecops_engine_tools.engine_sca.engine_license.src.infrastructure.driven_adapters.grant_tool.grant_manager_scan.os.path.exists",
    return_value=True,
)
@patch(
    "devsecops_engine_tools.engine_sca.engine_license.src.infrastructure.driven_adapters.grant_tool.grant_manager_scan.subprocess.run"
)
def test_run_grant_writes_output(mock_run, mock_exists, mock_getsize):
    mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
    scan = GrantScan()
    result = scan._run_grant(
        "grant", "img:tag", "svc", "json", True, False
    )
    assert result == "svc_grant.json"
    mock_run.assert_called_once()
    cmd = mock_run.call_args[0][0]
    assert "list" in cmd and "img:tag" in cmd and "--quiet" in cmd
    assert "-f" in cmd and "svc_grant.json" in cmd
    # We must NOT pass policy / non-spdx / osi-approved any more.
    assert "-c" not in cmd
    assert "--non-spdx" not in cmd
    assert "--osi-approved" not in cmd


@patch(
    "devsecops_engine_tools.engine_sca.engine_license.src.infrastructure.driven_adapters.grant_tool.grant_manager_scan.os.path.exists",
    return_value=False,
)
@patch(
    "devsecops_engine_tools.engine_sca.engine_license.src.infrastructure.driven_adapters.grant_tool.grant_manager_scan.subprocess.run"
)
def test_run_grant_no_output(mock_run, mock_exists):
    mock_run.return_value = MagicMock(stdout="", stderr="boom", returncode=2)
    scan = GrantScan()
    assert scan._run_grant("grant", "/x", "svc", "json", False, False) is None


@patch.object(GrantScan, "_run_grant", return_value="report.json")
@patch.object(GrantScan, "_resolve_binary", return_value="grant")
def test_run_tool_license_sca_happy_path(mock_bin, mock_run):
    scan = GrantScan()
    out = scan.run_tool_license_sca(
        {"GRANT": {"GRANT_VERSION": "0.2.5"}},
        _base_args(image_to_scan="img:tag"),
        {},
        "svc",
        to_scan="/tmp/x",
        sbom_path=None,
        image_to_scan="img:tag",
        secret_tool=None,
    )
    assert out == "report.json"


@patch.object(GrantScan, "_resolve_binary", return_value=None)
def test_run_tool_license_sca_no_binary(mock_bin):
    scan = GrantScan()
    out = scan.run_tool_license_sca(
        {}, _base_args(), {}, "svc", "/tmp", None, None, None
    )
    assert out is None


def test_get_license_context_from_results_success(tmp_path):
    import json

    license_data = {
        "metadata": {"pipeline_name": "svc"},
        "dependencies": [
            {
                "name": "lodash",
                "version": "4.17.21",
                "licenses": ["MIT"],
                "policy_applied": "ok",
                "policy_reason": "compliant SPDX license",
                "policy_pattern_matched": None,
            },
            {
                "name": "ngrx",
                "version": "1.0.0",
                "licenses": ["AGPL-3.0"],
                "policy_applied": "fail",
                "policy_reason": "matches FAIL pattern 'AGPL-*'",
                "policy_pattern_matched": "AGPL-*",
            },
            {
                "name": "biz-lib",
                "version": "2.0.0",
                "licenses": ["BUSL-1.1"],
                "policy_applied": "warn",
                "policy_reason": "matches WARN pattern 'BUSL-*'",
                "policy_pattern_matched": "BUSL-*",
            },
            {
                "name": "jakarta.servlet-api",
                "version": "6.1.0",
                "licenses": ["EPL-2.0", "GPL-2.0-with-classpath-exception"],
                "policy_applied": "warn",
                "policy_reason": "matches WARN pattern 'EPL-*'",
                "policy_pattern_matched": "EPL-*",
            },
            {
                "name": "no-lic",
                "version": "0.1.0",
                "licenses": [],
                "policy_applied": "unlicensed",
                "policy_reason": "no license detected",
                "policy_pattern_matched": None,
            },
            {
                "name": "weird-pkg",
                "version": "0.0.1",
                "licenses": ["Custom License"],
                "policy_applied": "unknown",
                "policy_reason": "non-SPDX license label",
                "policy_pattern_matched": None,
            },
        ],
    }
    path = tmp_path / "svc_LICENSE.json"
    path.write_text(json.dumps(license_data))

    scan = GrantScan()
    result = scan.get_license_context_from_results(str(path))

    # Only fail and warn appear in context
    assert len(result) == 3
    assert result[0].name == "ngrx"
    assert result[0].severity == "critical"
    assert result[1].name == "biz-lib"
    assert result[1].severity == "medium"
    assert result[2].name == "jakarta.servlet-api"
    assert result[2].severity == "medium"
    assert result[0].priority is None
