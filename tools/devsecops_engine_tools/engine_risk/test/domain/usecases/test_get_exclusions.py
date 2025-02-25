from unittest.mock import MagicMock, patch
from devsecops_engine_tools.engine_risk.src.domain.usecases.get_exclusions import (
    GetExclusions,
)


@patch(
    "devsecops_engine_tools.engine_risk.src.domain.usecases.get_exclusions.GetExclusions._get_unique_tags"
)
@patch(
    "devsecops_engine_tools.engine_risk.src.domain.usecases.get_exclusions.GetExclusions._get_risk_exclusions"
)
@patch(
    "devsecops_engine_tools.engine_risk.src.domain.usecases.get_exclusions.GetExclusions._get_exclusions_by_practice"
)
def test_process(
    mock_get_exclusions_by_practice, mock_get_risk_exclusions, mock_get_unique_tags
):
    mock_get_unique_tags.return_value = ["tag1", "tag2"]

    get_exclusions = GetExclusions(
        MagicMock(),
        {"remote_config_repo": "repo", "remote_config_branch": "repo"},
        MagicMock(),
        {"EXCLUSIONS_PATHS": {"tag1": "path1"}},
        MagicMock(),
        "pipeline_name",
        MagicMock(),
    )
    exclusions = get_exclusions.process()

    # Ajustar la aserción para comparar con la tupla retornada
    assert exclusions == ([], 0)
    mock_get_unique_tags.assert_called_once()
    mock_get_risk_exclusions.assert_called_once()
    mock_get_exclusions_by_practice.assert_called_once()


@patch(
    "devsecops_engine_tools.engine_risk.src.domain.usecases.get_exclusions.GetExclusions._get_exclusions"
)
def test_get_risk_exclusions(mock_get_exclusions):
    get_exclusions = GetExclusions(
        MagicMock(),
        MagicMock(),
        MagicMock(),
        MagicMock(),
        MagicMock(),
        "pipeline_name",
        MagicMock(),
    )
    exclusions = get_exclusions._get_risk_exclusions()

    assert exclusions == mock_get_exclusions.return_value
    mock_get_exclusions.assert_called_once()


@patch(
    "devsecops_engine_tools.engine_risk.src.domain.usecases.get_exclusions.GetExclusions._get_exclusions"
)
def test_get_exclusions_by_practice(mock_get_exclusions):
    get_exclusions = GetExclusions(
        MagicMock(),
        MagicMock(),
        MagicMock(),
        MagicMock(),
        MagicMock(),
        "pipeline_name",
        MagicMock(),
    )
    exclusions = get_exclusions._get_exclusions_by_practice(MagicMock(), "key", "path")

    assert exclusions == mock_get_exclusions.return_value
    mock_get_exclusions.assert_called_once()


@patch(
    "devsecops_engine_tools.engine_risk.src.domain.usecases.get_exclusions.Exclusions"
)
def test_get_exclusions(mock_exclusions):
    config = {
        "All": {
            "RISK": [
                {
                    "id": "id",
                    "where": "where",
                    "create_date": "create_date",
                    "expired_date": "expired_date",
                    "severity": "severity",
                    "reason": "reason",
                }
            ]
        }
    }

    get_exclusions = GetExclusions(
        MagicMock(),
        MagicMock(),
        MagicMock(),
        MagicMock(),
        MagicMock(),
        ["service1", "service2"],
        MagicMock(),
    )
    exclusions = get_exclusions._get_exclusions(config, "RISK")

    assert exclusions == [mock_exclusions.return_value]


def test_get_unique_tags():
    findings = [
        MagicMock(tags=["tag1", "tag2"]),
        MagicMock(tags=["tag2", "tag3"]),
    ]
    get_exclusions = GetExclusions(
        MagicMock(),
        MagicMock(),
        findings,
        MagicMock(),
        MagicMock(),
        "pipeline_name",
        MagicMock(),
    )
    unique_tags = get_exclusions._get_unique_tags()

    assert len(unique_tags) == 3


from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock, patch


@patch(
    "devsecops_engine_tools.engine_risk.src.domain.usecases.get_exclusions.Exclusions",
    side_effect=lambda **kwargs: kwargs,
)
@patch("devsecops_engine_tools.engine_risk.src.domain.usecases.get_exclusions.datetime")
def test_get_exclusions_new_vuln(mock_datetime, mock_exclusions):
    fixed_date = datetime(2023, 1, 10)
    mock_datetime.now.return_value = fixed_date
    mock_datetime.strptime.side_effect = lambda s, fmt: datetime.strptime(s, fmt)

    finding = SimpleNamespace(publish_date="2023-01-10", id="123")

    get_exclusions = GetExclusions(
        devops_platform_gateway=MagicMock(),
        dict_args={"remote_config_repo": "repo", "remote_config_branch": "branch"},
        findings=[],
        risk_config=MagicMock(),
        risk_exclusions=MagicMock(),
        services=["service1"],
        active_findings=[finding],
    )

    exclusions, count = get_exclusions._get_exclusions_new_vuln()

    expected_create_date = fixed_date.strftime("%d%m%Y")
    expected_expired_date = (fixed_date + timedelta(days=5)).strftime("%d%m%Y")

    assert count == 1
    assert len(exclusions) == 1
    exclusion = exclusions[0]
    assert exclusion["create_date"] == expected_create_date
    assert exclusion["expired_date"] == expected_expired_date
    assert exclusion["reason"] == "New vulnerability in the industry"
