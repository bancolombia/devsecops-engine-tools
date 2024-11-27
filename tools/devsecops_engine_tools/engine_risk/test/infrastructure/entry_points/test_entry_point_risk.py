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
@patch(
    "devsecops_engine_tools.engine_risk.src.infrastructure.entry_points.entry_point_risk.AddData"
)
@patch(
    "devsecops_engine_tools.engine_risk.src.infrastructure.entry_points.entry_point_risk.GetExclusions"
)
def test_init_engine_risk(
    mock_get_exclusions, mock_add_data, mock_break_build, mock_handle_filters
):
    dict_args = {"remote_config_repo": "remote_config"}
    findings = ["finding1", "finding2"]
    services = ["service1", "service2"]
    vm_exclusions = ["exclusion1", "exclusion2"]
    mock_devops_platform_gateway = MagicMock()
    mock_print_table_gateway = MagicMock()

    init_engine_risk(
        MagicMock(),
        mock_devops_platform_gateway,
        mock_print_table_gateway,
        dict_args,
        findings,
        services,
        vm_exclusions,
    )

    assert mock_devops_platform_gateway.get_remote_config.call_count == 2
    mock_handle_filters.return_value.filter.assert_called_once_with(findings)
    mock_handle_filters.return_value.filter_duplicated.assert_called_once()
    mock_handle_filters.return_value.filter_tags_days.assert_called_once()
    mock_add_data.assert_called_once()
    mock_get_exclusions.assert_called_once()
    mock_break_build.assert_called_once()


@patch(
    "devsecops_engine_tools.engine_risk.src.infrastructure.entry_points.entry_point_risk.logger"
)
def test_init_engine_risk_no_findings(mock_logger):
    dict_args = {"remote_config_repo": "remote_config"}
    findings = []
    services = ["service1", "service2"]
    vm_exclusions = ["exclusion1", "exclusion2"]
    mock_devops_platform_gateway = MagicMock()
    mock_print_table_gateway = MagicMock()

    init_engine_risk(
        MagicMock(),
        mock_devops_platform_gateway,
        mock_print_table_gateway,
        dict_args,
        findings,
        services,
        vm_exclusions,
    )

    mock_logger.info.assert_called_once_with(
        "No findings found in Vulnerability Management Platform"
    )
