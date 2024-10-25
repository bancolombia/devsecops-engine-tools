from unittest.mock import MagicMock, patch
from devsecops_engine_tools.engine_risk.src.infrastructure.entry_points.entry_point_risk import (
    init_engine_risk,
    process_findings,
)


@patch(
    "devsecops_engine_tools.engine_risk.src.infrastructure.entry_points.entry_point_risk.process_findings"
)
def test_init_engine_risk_process(mock_process):
    dict_args = {"remote_config_repo": "remote_config"}
    findings = ["finding1", "finding2"]
    services = ["service1", "service2"]
    vm_exclusions = ["exclusion1", "exclusion2"]

    init_engine_risk(
        MagicMock(),
        MagicMock(),
        MagicMock(),
        dict_args,
        findings,
        services,
        vm_exclusions,
    )

    mock_process.assert_called_once()


@patch("builtins.print")
def test_process_findings_no_findings(mock_print):
    findings = []

    process_findings(
        findings,
        MagicMock(),
        MagicMock(),
        MagicMock(),
        MagicMock(),
        MagicMock(),
        MagicMock(),
        MagicMock(),
        MagicMock(),
    )

    mock_print.assert_called_once_with(
        "No findings found in Vulnerability Management Platform"
    )


@patch(
    "devsecops_engine_tools.engine_risk.src.infrastructure.entry_points.entry_point_risk.HandleFilters"
)
@patch(
    "devsecops_engine_tools.engine_risk.src.infrastructure.entry_points.entry_point_risk.process_active_findings"
)
def test_process_findings(mock_process_active, mock_filters):
    findings = ["finding1", "finding2"]
    mock_filters.return_value.filter.return_value = []

    process_findings(
        findings,
        MagicMock(),
        MagicMock(),
        MagicMock(),
        MagicMock(),
        MagicMock(),
        MagicMock(),
        MagicMock(),
        MagicMock(),
    )

    mock_process_active.assert_called_once()


@patch(
    "devsecops_engine_tools.engine_risk.src.infrastructure.entry_points.entry_point_risk.GetExclusions"
)
@patch(
    "devsecops_engine_tools.engine_risk.src.infrastructure.entry_points.entry_point_risk.AddData"
)
@patch(
    "devsecops_engine_tools.engine_risk.src.infrastructure.entry_points.entry_point_risk.BreakBuild"
)
def test_process_active_findings(mock_break, mock_add, mock_exclusions):

    process_findings(
        MagicMock(),
        MagicMock(),
        MagicMock(),
        MagicMock(),
        MagicMock(),
        MagicMock(),
        MagicMock(),
        MagicMock(),
        MagicMock(),
    )

    mock_add.return_value.process.assert_called_once()
    mock_exclusions.return_value.process.assert_called_once()
    mock_break.return_value.process.assert_called_once()
