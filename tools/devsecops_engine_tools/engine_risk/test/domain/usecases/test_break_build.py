import unittest
from unittest.mock import MagicMock, patch, Mock
from devsecops_engine_tools.engine_risk.src.domain.usecases.break_build import (
    BreakBuild,
)
from devsecops_engine_tools.engine_core.src.domain.model.report import (
    Report,
)
from devsecops_engine_tools.engine_core.src.domain.model.exclusions import (
    Exclusions,
)


@patch(
    "devsecops_engine_tools.engine_risk.src.domain.usecases.break_build.BreakBuild._risk_management_control"
)
@patch(
    "devsecops_engine_tools.engine_risk.src.domain.usecases.break_build.BreakBuild._apply_exclusions"
)
@patch(
    "devsecops_engine_tools.engine_risk.src.domain.usecases.break_build.BreakBuild._tag_blacklist_control"
)
@patch(
    "devsecops_engine_tools.engine_risk.src.domain.usecases.break_build.BreakBuild._risk_score_control"
)
@patch(
    "devsecops_engine_tools.engine_risk.src.domain.usecases.break_build.BreakBuild._print_exclusions"
)
@patch(
    "devsecops_engine_tools.engine_risk.src.domain.usecases.break_build.BreakBuild._map_applied_exclusion"
)
@patch(
    "devsecops_engine_tools.engine_risk.src.domain.usecases.break_build.BreakBuild._breaker"
)
@patch("copy.deepcopy")
def test_process(
    deepcopy,
    breaker,
    map_applied_exclusion,
    print_exclusions,
    risk_score_control,
    tag_blacklist_control,
    apply_exclusions,
    risk_management_control,
):
    report_list = [Report(risk_score=10)]
    exclusions = [Exclusions(severity="severity", id="id", reason="reason")]
    remote_config = {"MESSAGE_INFO": "message"}
    apply_exclusions.return_value = (report_list, exclusions)

    break_build = BreakBuild(
        MagicMock(),
        MagicMock(),
        remote_config,
        [],
        [],
        [],
        [],
    )
    break_build.break_build = True
    result = break_build.process()

    risk_management_control.assert_called_once()
    apply_exclusions.assert_called_once()
    deepcopy.assert_called_once()
    tag_blacklist_control.assert_called_once()
    risk_score_control.assert_called_once()
    print_exclusions.assert_called_once()
    map_applied_exclusion.assert_called_once()
    breaker.assert_called_once()


def test_breaker_break():
    devops_platform_gateway = MagicMock()
    break_build = BreakBuild(
        devops_platform_gateway,
        MagicMock(),
        {},
        [],
        [],
        [],
        [],
    )
    break_build.break_build = True
    break_build._breaker()

    devops_platform_gateway.result_pipeline.assert_called_with("failed")


def test_breaker_not_break():
    devops_platform_gateway = MagicMock()
    break_build = BreakBuild(
        devops_platform_gateway,
        MagicMock(),
        {},
        [],
        [],
        [],
        [],
    )
    break_build.break_build = False
    break_build._breaker()

    devops_platform_gateway.result_pipeline.assert_called_with("succeeded")


def test_risk_management_control_greater():
    all_report = [
        Report(mitigated=True),
        Report(mitigated=False),
        Report(mitigated=False),
    ]
    risk_management_value = round((1 / 3) * 100, 3)
    remote_config = {"THRESHOLD": {"RISK_MANAGEMENT": 10}}
    risk_threshold = remote_config["THRESHOLD"]["RISK_MANAGEMENT"]
    devops_platform_gateway = MagicMock()
    break_build = BreakBuild(
        devops_platform_gateway,
        MagicMock(),
        remote_config,
        [],
        [],
        [],
        [],
    )
    break_build._risk_management_control(all_report)

    devops_platform_gateway.message.assert_called_with(
        "succeeded",
        f"Risk Management {risk_management_value}% is greater than {risk_threshold}%",
    )


def test_risk_management_control_close():
    all_report = [
        Report(mitigated=True),
        Report(mitigated=False),
        Report(mitigated=False),
    ]
    risk_management_value = round((1 / 3) * 100, 3)
    remote_config = {"THRESHOLD": {"RISK_MANAGEMENT": 30}}
    risk_threshold = remote_config["THRESHOLD"]["RISK_MANAGEMENT"]
    devops_platform_gateway = MagicMock()
    break_build = BreakBuild(
        devops_platform_gateway,
        MagicMock(),
        remote_config,
        [],
        [],
        [],
        [],
    )
    break_build._risk_management_control(all_report)

    devops_platform_gateway.message.assert_called_with(
        "warning",
        f"Risk Management {risk_management_value}% is close to {risk_threshold}%",
    )


def test_risk_management_control_less():
    all_report = [
        Report(mitigated=True),
        Report(mitigated=False),
        Report(mitigated=False),
    ]
    risk_management_value = round((1 / 3) * 100, 3)
    remote_config = {"THRESHOLD": {"RISK_MANAGEMENT": 50}}
    risk_threshold = remote_config["THRESHOLD"]["RISK_MANAGEMENT"]
    devops_platform_gateway = MagicMock()
    break_build = BreakBuild(
        devops_platform_gateway,
        MagicMock(),
        remote_config,
        [],
        [],
        [],
        [],
    )
    break_build._risk_management_control(all_report)

    devops_platform_gateway.message.assert_called_with(
        "error",
        f"Risk Management {risk_management_value}% is less than {risk_threshold}%",
    )


def test_get_applied_exclusion_id():
    report = Report(id="id")
    exclusion = Exclusions(id="id")
    break_build = BreakBuild(
        MagicMock(),
        MagicMock(),
        {},
        [],
        [],
        [],
        [],
    )
    break_build.exclusions = [exclusion]
    result = break_build._get_applied_exclusion(report)

    assert result == exclusion


def test_get_applied_exclusion_vul_id_tool():
    report = Report(vul_id_tool="id")
    exclusion = Exclusions(id="id")
    break_build = BreakBuild(
        MagicMock(),
        MagicMock(),
        {},
        [],
        [],
        [],
        [],
    )
    break_build.exclusions = [exclusion]
    result = break_build._get_applied_exclusion(report)

    assert result == exclusion


def test_map_applied_exclusion():
    exclusions = [
        Exclusions(
            severity="severity",
            id="id",
            where="where",
            create_date="create_date",
            expired_date="expired_date",
            reason="reason",
        )
    ]
    expected = [
        {
            "severity": "severity",
            "id": "id",
            "where": "where",
            "create_date": "create_date",
            "expired_date": "expired_date",
            "reason": "reason",
        }
    ]

    break_build = BreakBuild(
        MagicMock(),
        MagicMock(),
        {},
        [],
        [],
        [],
        [],
    )
    result = break_build._map_applied_exclusion(exclusions)

    assert result == expected
