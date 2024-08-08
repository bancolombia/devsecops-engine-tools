from unittest.mock import MagicMock, patch
from devsecops_engine_tools.engine_risk.src.infrastructure.entry_points.entry_point_risk import (
    init_engine_risk,
    should_skip_analysis,
    process_findings,
)


@patch(
    "devsecops_engine_tools.engine_risk.src.infrastructure.entry_points.entry_point_risk.should_skip_analysis"
)
@patch("builtins.print")
def test_init_engine_risk_skip(mock_print, mock_skip):
    dict_args = {"remote_config_repo": "remote_config"}
    findings = ["finding1", "finding2"]
    mock_skip.return_value = True

    init_engine_risk(MagicMock(), MagicMock(), dict_args, findings)

    mock_print.assert_called_once_with("Tool skipped by DevSecOps Policy.")


@patch(
    "devsecops_engine_tools.engine_risk.src.infrastructure.entry_points.entry_point_risk.should_skip_analysis"
)
@patch(
    "devsecops_engine_tools.engine_risk.src.infrastructure.entry_points.entry_point_risk.process_findings"
)
def test_init_engine_risk_process(mock_process, mock_skip):
    dict_args = {"remote_config_repo": "remote_config"}
    findings = ["finding1", "finding2"]
    mock_skip.return_value = False

    init_engine_risk(MagicMock(), MagicMock(), dict_args, findings)

    mock_process.assert_called_once()


def test_should_skip_analysis():
    remote_config = {"IGNORE_ANALYSIS_PATTERN": "pattern"}
    pipeline_name = "pipeline"
    exclusions = {"pipeline": {"SKIP_TOOL": 1}}

    assert should_skip_analysis(remote_config, pipeline_name, exclusions) == True


@patch("builtins.print")
def test_process_findings_no_findings(mock_print):
    findings = []

    process_findings(findings, MagicMock(), MagicMock(), MagicMock())

    mock_print.assert_called_once_with(
        "No findings found in Vulnerability Management Platform"
    )


@patch("builtins.print")
@patch(
    "devsecops_engine_tools.engine_risk.src.infrastructure.entry_points.entry_point_risk.HandleFilters"
)
def test_process_findings_no_active_findings(mock_filters, mock_print):
    findings = ["finding1", "finding2"]
    mock_filters.return_value.filter.return_value = []

    process_findings(findings, MagicMock(), MagicMock(), MagicMock())

    mock_print.assert_called_once_with(
        "No active findings found in Vulnerability Management Platform"
    )


@patch(
    "devsecops_engine_tools.engine_risk.src.infrastructure.entry_points.entry_point_risk.HandleFilters"
)
@patch(
    "devsecops_engine_tools.engine_risk.src.infrastructure.entry_points.entry_point_risk.AddData"
)
@patch(
    "devsecops_engine_tools.engine_risk.src.infrastructure.entry_points.entry_point_risk.BreakBuild"
)
def test_process_findings(mock_break, mock_add, mock_filters):
    findings = ["finding1", "finding2"]
    active_findings = ["active1", "active2"]
    mock_filters.return_value.filter.return_value = active_findings

    process_findings(findings, MagicMock(), MagicMock(), MagicMock())

    mock_add.assert_called_once_with(active_findings)
    mock_break.assert_called_once()
