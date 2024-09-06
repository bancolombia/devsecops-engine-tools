from unittest.mock import patch, Mock
from devsecops_engine_tools.engine_risk.src.infrastructure.driven_adapters.first_csv.first_epss_csv import (
    FirstCsv,
)


@patch("requests.get")
@patch("gzip.open")
@patch("io.BytesIO")
@patch(
    "devsecops_engine_tools.engine_risk.src.infrastructure.driven_adapters.first_csv.first_epss_csv.logger.info"
)
def test_download_epss_data(mock_info, mock_gzip_open, mock_bytes, mock_requests_get):
    mock_requests_get.return_value.status_code = 200

    FirstCsv().download_epss_data()

    mock_gzip_open.assert_called_once()
    mock_info.assert_called_once()


@patch("csv.reader")
@patch("io.StringIO")
def test_get_epss_dict(mock_stringio, mock_csv_reader):
    mock_csv_reader.return_value = [["row1", "row2"], ["row3", "row4"]]

    epss_dict = FirstCsv().get_epss_dict("epss_data")

    assert epss_dict == {"row1": "row2", "row3": "row4"}


@patch(
    "devsecops_engine_tools.engine_risk.src.infrastructure.driven_adapters.first_csv.first_epss_csv.FirstCsv.download_epss_data"
)
@patch(
    "devsecops_engine_tools.engine_risk.src.infrastructure.driven_adapters.first_csv.first_epss_csv.FirstCsv.get_epss_dict"
)
def test_add_epss_data(mock_get_epss_dict, mock_download_epss_data):
    mock_get_epss_dict.return_value = {"CVE-2021-1234": "10"}

    findings = [
        Mock(id="CVE-2021-1234", epss_score=0),
        Mock(id="CVE-2021-1235", epss_score=0),
    ]

    updated_findings = FirstCsv().add_epss_data(findings)

    assert updated_findings[0].epss_score == 10
    assert updated_findings[1].epss_score == 0
