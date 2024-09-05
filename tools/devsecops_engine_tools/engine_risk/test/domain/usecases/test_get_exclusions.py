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
        {"remote_config_repo": "repo"},
        MagicMock(),
        {"EXCLUSIONS_PATHS": {"tag1": "path1"}},
        MagicMock(),
        "pipeline_name",
    )
    exclusions = get_exclusions.process()

    assert exclusions == []
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
        "pipeline_name",
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
    )
    unique_tags = get_exclusions._get_unique_tags()

    assert len(unique_tags) == 3
