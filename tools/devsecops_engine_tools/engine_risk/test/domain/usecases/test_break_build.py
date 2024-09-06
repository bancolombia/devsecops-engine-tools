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
    "devsecops_engine_tools.engine_risk.src.domain.usecases.break_build.BreakBuild._remediation_rate_control"
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
    remediation_rate_control,
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

    remediation_rate_control.assert_called_once()
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


def test_remediation_rate_control_greater():
    all_report = [
        Report(mitigated=True),
        Report(mitigated=False),
        Report(mitigated=False),
    ]
    remediation_rate_value = round((1 / 3) * 100, 3)
    remote_config = {"THRESHOLD": {"REMEDIATION_RATE": 10}}
    risk_threshold = remote_config["THRESHOLD"]["REMEDIATION_RATE"]
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
    break_build._remediation_rate_control(all_report)

    devops_platform_gateway.message.assert_called_with(
        "succeeded",
        f"Remediation Rate {remediation_rate_value}% is greater than {risk_threshold}%",
    )


def test_remediation_rate_control_close():
    all_report = [
        Report(mitigated=True),
        Report(mitigated=False),
        Report(mitigated=False),
    ]
    remediation_rate_value = round((1 / 3) * 100, 3)
    remote_config = {"THRESHOLD": {"REMEDIATION_RATE": 30}}
    risk_threshold = remote_config["THRESHOLD"]["REMEDIATION_RATE"]
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
    break_build._remediation_rate_control(all_report)

    devops_platform_gateway.message.assert_called_with(
        "warning",
        f"Remediation Rate {remediation_rate_value}% is close to {risk_threshold}%",
    )


def test_remediation_rate_control_less():
    all_report = [
        Report(mitigated=True),
        Report(mitigated=False),
        Report(mitigated=False),
    ]
    remediation_rate_value = round((1 / 3) * 100, 3)
    remote_config = {"THRESHOLD": {"REMEDIATION_RATE": 50}}
    risk_threshold = remote_config["THRESHOLD"]["REMEDIATION_RATE"]
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
    break_build._remediation_rate_control(all_report)

    devops_platform_gateway.message.assert_called_with(
        "error",
        f"Remediation Rate {remediation_rate_value}% is less than {risk_threshold}%",
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


def test_get_applied_exclusion_vuln_id_from_tool():
    report = Report(vuln_id_from_tool="id")
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


@patch(
    "devsecops_engine_tools.engine_risk.src.domain.usecases.break_build.BreakBuild._get_applied_exclusion"
)
def test_apply_exclusions_vuln_id_from_tool(get_applied_exclusion):
    report_list = [Report(vuln_id_from_tool="id")]
    exclusions = [Exclusions(id="id")]
    break_build = BreakBuild(
        MagicMock(),
        MagicMock(),
        {},
        [],
        [],
        [],
        [],
    )
    break_build.exclusions = exclusions

    break_build._apply_exclusions(report_list)

    get_applied_exclusion.assert_called_with(report_list[0])


@patch(
    "devsecops_engine_tools.engine_risk.src.domain.usecases.break_build.BreakBuild._get_applied_exclusion"
)
def test_apply_exclusions_id(get_applied_exclusion):
    report_list = [Report(id="id")]
    exclusions = [Exclusions(id="id")]
    break_build = BreakBuild(
        MagicMock(),
        MagicMock(),
        {},
        [],
        [],
        [],
        [],
    )
    break_build.exclusions = exclusions

    break_build._apply_exclusions(report_list)

    get_applied_exclusion.assert_called_with(report_list[0])


@patch(
    "devsecops_engine_tools.engine_risk.src.domain.usecases.break_build.BreakBuild._get_applied_exclusion"
)
def test_apply_exclusions_vuln_id_from_tool(get_applied_exclusion):
    report_list = [Report(id="id1")]
    exclusions = [Exclusions(id="id")]
    break_build = BreakBuild(
        MagicMock(),
        MagicMock(),
        {},
        [],
        [],
        [],
        [],
    )
    break_build.exclusions = exclusions

    break_build._apply_exclusions(report_list)

    get_applied_exclusion.assert_not_called()


def test_tag_blacklist_control_error():
    report_list = [Report(vuln_id_from_tool="id1", tags=["blacklisted"], age=10)]
    remote_config = {
        "THRESHOLD": {
            "TAG_BLACKLIST": ["blacklisted"],
            "TAG_MAX_AGE": 5,
        }
    }
    tag_age_threshold = remote_config["THRESHOLD"]["TAG_MAX_AGE"]
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
    break_build._tag_blacklist_control(report_list)

    devops_platform_gateway.message.assert_called_once_with(
        "error",
        f"Report {report_list[0].vuln_id_from_tool} with tag {report_list[0].tags[0]} is blacklisted and age {report_list[0].age} is above threshold {tag_age_threshold}",
    )


def test_tag_blacklist_control_warning():
    report_list = [Report(vuln_id_from_tool="id2", tags=["blacklisted"], age=3)]
    remote_config = {
        "THRESHOLD": {
            "TAG_BLACKLIST": ["blacklisted"],
            "TAG_MAX_AGE": 5,
        }
    }
    tag_age_threshold = remote_config["THRESHOLD"]["TAG_MAX_AGE"]
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
    break_build._tag_blacklist_control(report_list)

    devops_platform_gateway.message.assert_called_once_with(
        "warning",
        f"Report {report_list[0].vuln_id_from_tool} with tag {report_list[0].tags[0]} is blacklisted but age {report_list[0].age} is below threshold {tag_age_threshold}",
    )


def test_risk_score_control_break():
    report_list = [Report(severity="high", epss_score=0, age=0, tags=["tag"])]
    remote_config = {
        "THRESHOLD": {"RISK_SCORE": 4},
        "WEIGHTS": {
            "severity": {"high": 5},
            "epss_score": 1,
            "age": 1,
            "tags": {"tag": 1},
        },
    }
    risk_score_threshold = remote_config["THRESHOLD"]["RISK_SCORE"]
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
    break_build._risk_score_control(report_list)

    devops_platform_gateway.message.assert_called_once_with(
        "error",
        f"There are findings with risk score greater than {risk_score_threshold}",
    )


def test_risk_score_control_not_break():
    report_list = [Report(severity="low", epss_score=0, age=0, tags=["tag"])]
    remote_config = {
        "THRESHOLD": {"RISK_SCORE": 4},
        "WEIGHTS": {
            "severity": {"high": 1},
            "epss_score": 1,
            "age": 1,
            "tags": {"tag": 1},
        },
    }
    risk_score_threshold = remote_config["THRESHOLD"]["RISK_SCORE"]
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
    break_build._risk_score_control(report_list)

    devops_platform_gateway.message.assert_called_once_with(
        "succeeded",
        f"There are no findings with risk score greater than {risk_score_threshold}",
    )


def test_print_exclusions():
    applied_exclusions = [
        {
            "severity": "severity",
            "id": "id",
            "where": "where",
            "create_date": "create_date",
            "expired_date": "expired_date",
            "reason": "reason",
        }
    ]
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
    break_build._print_exclusions(applied_exclusions)

    devops_platform_gateway.message.assert_called_once_with(
        "warning",
        "Bellow are all findings that were excepted",
    )
