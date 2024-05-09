from unittest.mock import MagicMock, patch
from devsecops_engine_tools.engine_risk.src.infrastructure.entry_points.entry_point_risk import (
    init_engine_risk,
)


@patch(
    "devsecops_engine_tools.engine_risk.src.infrastructure.entry_points.entry_point_risk.HandleFilters"
)
@patch(
    "devsecops_engine_tools.engine_risk.src.infrastructure.entry_points.entry_point_risk.BreakBuild"
)
def test_init_engine_risk(mock_break_build, mock_handle_filters):
    dict_args = {"remote_config_repo": "remote_config"}
    findings = ["finding1", "finding2"]

    init_engine_risk(MagicMock(), MagicMock(), dict_args, findings)

    mock_handle_filters.assert_called_once()
    mock_break_build.assert_called_once()


@patch("builtins.print")
def test_init_engine_risk_no_findigs(mock_print):
    dict_args = {"remote_config_repo": "remote_config"}
    findings = []

    init_engine_risk(MagicMock(), MagicMock(), dict_args, findings)

    mock_print.assert_called_with(
        "No Findings found in Vulnerability Management Platform"
    )
