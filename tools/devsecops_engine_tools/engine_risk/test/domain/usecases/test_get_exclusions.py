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
    "devsecops_engine_tools.engine_risk.src.domain.usecases.get_exclusions.GetExclusions._create_exclusion"
)
def test_get_vm_exclusions(mock_create_exclusion):
    total_findings = [MagicMock(risk_accepted=True), MagicMock(false_p=True)]
    get_exclusions = GetExclusions(
        MagicMock(),
        MagicMock(),
        MagicMock(),
        MagicMock(),
        MagicMock(),
        "pipeline_name",
    )
    exclusions = get_exclusions.get_vm_exclusions(total_findings)

    assert exclusions == [
        mock_create_exclusion.return_value,
        mock_create_exclusion.return_value,
    ]
    mock_create_exclusion.assert_called()


@patch(
    "devsecops_engine_tools.engine_risk.src.domain.usecases.get_exclusions.Exclusions"
)
@patch(
    "devsecops_engine_tools.engine_risk.src.domain.usecases.get_exclusions.GetExclusions._format_date_to_dd_format"
)
def test_create_exclusion(mock_format_date_to_dd_format, mock_exclusions):
    get_exclusions = GetExclusions(
        MagicMock(),
        MagicMock(),
        MagicMock(),
        MagicMock(),
        MagicMock(),
        "pipeline_name",
    )
    finding = MagicMock(
        vuln_id_from_tool="vuln_id_from_tool",
        id=[{"vulnerability_id": "vulnerability_id"}],
        where="where",
        severity="severity",
    )
    exclusion = get_exclusions._create_exclusion(finding, "reason")

    assert exclusion == mock_exclusions.return_value
    mock_format_date_to_dd_format.assert_called()
    mock_exclusions.assert_called_once_with(
        id="vuln_id_from_tool",
        where="where",
        create_date=mock_format_date_to_dd_format.return_value,
        expired_date=mock_format_date_to_dd_format.return_value,
        severity="severity",
        reason="reason",
    )


def test_format_date_to_dd_format():
    get_exclusions = GetExclusions(
        MagicMock(),
        MagicMock(),
        MagicMock(),
        MagicMock(),
        MagicMock(),
        "pipeline_name",
    )
    date = get_exclusions._format_date_to_dd_format("2021-01-01T00:00:00Z")

    assert date == "01012021"


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
