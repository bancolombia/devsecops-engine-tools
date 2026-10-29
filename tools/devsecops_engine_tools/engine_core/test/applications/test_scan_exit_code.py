import subprocess
import sys
from unittest.mock import Mock, patch

import pytest

from devsecops_engine_tools.engine_core.src.applications import runner_engine_core
from devsecops_engine_tools.engine_core.src.domain.model.exclusions import Exclusions
from devsecops_engine_tools.engine_core.src.domain.model.finding import (
    Category,
    Finding,
    Priority,
)
from devsecops_engine_tools.engine_core.src.domain.model.input_core import InputCore
from devsecops_engine_tools.engine_core.src.domain.model.threshold import Threshold
from devsecops_engine_tools.engine_core.src.domain.usecases.break_build import (
    BreakBuild,
)
from devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.azure.azure_devops import (
    AzureDevops,
)
from devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.github.github_actions import (
    GithubActions,
)
from devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.runtime_local.runtime_local import (
    RuntimeLocal,
)
from devsecops_engine_tools.engine_risk.src.domain.usecases.break_build import (
    BreakBuild as RiskBreakBuild,
)


PLATFORMS = [AzureDevops, GithubActions, RuntimeLocal]
RUNNER = "devsecops_engine_tools.engine_core.src.applications.runner_engine_core"


@pytest.mark.parametrize("platform", PLATFORMS)
def test_pipeline_failure_is_sticky_and_instance_local(platform):
    gateway = platform()
    assert gateway.exit_code == 0
    gateway.result_pipeline("succeeded_with_issues")
    assert gateway.exit_code == 0
    gateway.result_pipeline("failed")
    gateway.result_pipeline("succeeded")
    gateway.result_pipeline("succeeded_with_issues")
    assert gateway.exit_code == 1
    assert platform().exit_code == 0


@pytest.mark.parametrize("platform", PLATFORMS)
@pytest.mark.parametrize(
    "scenario,expected",
    [
        ("no_findings", 0),
        ("below_threshold", 0),
        ("at_threshold", 1),
        ("above_threshold", 1),
        ("priority_threshold", 1),
        ("cve_policy", 1),
        ("compliance", 1),
        ("excluded", 0),
        ("warning", 0),
    ],
)
def test_scan_policy_exit_code(platform, scenario, expected):
    gateway = platform()
    finding = Finding(
        id="CVE-2025-0001",
        cvss=9.0,
        where="all",
        description="Test finding",
        severity="critical",
        priority=Priority(score=9.0, scale="very critical"),
        identification_date="2025-01-01",
        published_date_cve=None,
        module="engine_iac",
        category=(
            Category.COMPLIANCE if scenario == "compliance" else Category.VULNERABILITY
        ),
        requirements="",
        tool="CHECKOV",
    )
    threshold = Threshold(
        {
            "VULNERABILITY": {"Critical": 2, "High": 10, "Medium": 10, "Low": 10},
            "COMPLIANCE": {"Critical": 1},
            "CVE": [finding.id] if scenario == "cve_policy" else [],
            "PRIORITY": {
                "Very Critical": 1,
                "Critical": 10,
                "High": 10,
                "Medium Low": 10,
            },
        }
    )
    exclusions = (
        [Exclusions(id=finding.id, where="all", severity="critical")]
        if scenario == "excluded"
        else []
    )
    input_core = InputCore(exclusions, threshold, "", "", "", "", "")
    manager = {
        "MODEL": "severity",
        "CLASSIFICATION": ["critical", "high", "medium", "low"],
    }
    if scenario == "priority_threshold":
        manager = {
            "MODEL": "priority",
            "CLASSIFICATION": ["very critical", "critical", "high", "medium low"],
        }
    count = {"no_findings": 0, "at_threshold": 2, "above_threshold": 3}.get(scenario, 1)
    with patch.object(gateway, "get_variable", return_value="release"), patch.object(
        sys, "stdout"
    ):
        BreakBuild(gateway, Mock()).process(
            [finding] * count,
            input_core,
            {"module": "engine_iac"},
            scenario == "warning",
            manager,
        )
    assert gateway.exit_code == expected


@pytest.mark.parametrize("platform", ["azure", "github", "local"])
@pytest.mark.parametrize("failed", [False, True])
def test_application_returns_pipeline_exit_code(platform, failed):
    args = {
        "platform_devops": platform,
        "remote_config_source": "local",
        "remote_config_repo": "config",
        "remote_config_branch": "",
    }

    def scan(*gateways):
        gateway = gateways[2]
        gateway.result_pipeline("failed" if failed else "succeeded_with_issues")
        gateway.result_pipeline("succeeded")

    with patch(f"{RUNNER}.get_inputs_from_cli", return_value=args), patch.object(
        RuntimeLocal, "get_remote_config", return_value={"TRACEBACK": False}
    ), patch(f"{RUNNER}.init_engine_core", side_effect=scan) as init:
        assert runner_engine_core.application_core() == int(failed)
    init.assert_called_once()


@pytest.mark.parametrize("early_failure", [False, True])
def test_application_returns_nonzero_on_execution_error(early_failure):
    args = {
        "platform_devops": "local",
        "remote_config_source": "local",
        "remote_config_repo": "config",
        "remote_config_branch": "",
    }
    with patch(
        f"{RUNNER}.get_inputs_from_cli",
        side_effect=RuntimeError("Input failure") if early_failure else None,
        return_value=args,
    ), patch.object(
        RuntimeLocal, "get_remote_config", return_value={"TRACEBACK": False}
    ), patch(
        f"{RUNNER}.init_engine_core", side_effect=RuntimeError("Scan failure")
    ), patch(
        f"{RUNNER}.logger"
    ) as logger:
        assert runner_engine_core.application_core() == 1
    logger.error.assert_called_once()


@pytest.mark.parametrize("platform", PLATFORMS)
def test_risk_failure_exit_code(platform):
    gateway = platform()
    breaker = RiskBreakBuild(gateway, Mock(), {}, [], [], [], [], {}, 0)
    breaker.break_build = True
    breaker._breaker()
    assert gateway.exit_code == 1


def test_application_finishes_metrics_after_policy_failure():
    args = {
        "platform_devops": "local",
        "remote_config_source": "local",
        "remote_config_repo": "config",
        "remote_config_branch": "",
        "module": "engine_risk",
        "send_metrics": "true",
    }
    config = {
        "BANNER": "Test",
        "ENGINE_RISK": {"ENABLED": True},
        "SBOM_MANAGER": {"TOOL": "SYFT"},
        "LICENSE_ANALYZER": {"TOOL": "dependency_track"},
    }
    entry_point = "devsecops_engine_tools.engine_core.src.infrastructure.entry_points.entry_point_core"
    results = {"risk": {"status": "failed"}}
    input_core = Mock()

    def risk(*gateways):
        gateways[2].result_pipeline("failed")
        return Mock(process=Mock(return_value=(results, input_core)))

    with patch(f"{RUNNER}.get_inputs_from_cli", return_value=args), patch.object(
        RuntimeLocal, "get_remote_config", return_value=config
    ), patch(f"{entry_point}.HandleRisk", side_effect=risk), patch(
        f"{entry_point}.MetricsManager"
    ) as metrics:
        assert runner_engine_core.application_core() == 1
    metrics.return_value.process.assert_called_once_with(
        config, input_core, args, results
    )


@pytest.mark.parametrize("entry_point", ["module", "console"])
@pytest.mark.parametrize("failed", [False, True])
def test_process_exit_code(entry_point, failed):
    script = f"""
import runpy
import sys
from unittest.mock import patch
from devsecops_engine_tools.engine_core.src.infrastructure.entry_points import entry_point_core
from devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.runtime_local.runtime_local import RuntimeLocal

def scan(*gateways):
    gateways[2].result_pipeline({"'failed'" if failed else "'succeeded'"})
    gateways[2].result_pipeline("succeeded")

sys.argv = ["devsecops-engine-tools", "--platform_devops", "local",
            "--remote_config_source", "local", "--remote_config_repo", "config",
            "--module", "engine_iac"]
with patch.object(entry_point_core, "init_engine_core", side_effect=scan), patch.object(
    RuntimeLocal, "get_remote_config", return_value={{"TRACEBACK": False}}
):
    if {entry_point!r} == "module":
        runpy.run_module({RUNNER!r}, run_name="__main__")
    else:
        from {RUNNER} import application_core
        sys.exit(application_core())
"""
    result = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, timeout=30
    )
    assert result.returncode == int(failed), result.stderr
