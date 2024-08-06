from unittest.mock import MagicMock, patch, Mock
from devsecops_engine_tools.engine_risk.src.domain.usecases.add_data import AddData


def test_init():
    findings = ["finding1", "finding2"]

    add_data = AddData(findings)

    assert add_data.findings == findings


@patch("requests.get")
@patch("gzip.open")
@patch("io.BytesIO")
@patch("devsecops_engine_tools.engine_risk.src.domain.usecases.add_data.logger.info")
def test_download_epss_data(mock_info, mock_gzip_open, mock_bytes, mock_requests_get):
    mock_requests_get.return_value.status_code = 200

    AddData([]).download_epss_data()

    mock_gzip_open.assert_called_once()
    mock_info.assert_called_once()


@patch("csv.reader")
@patch("io.StringIO")
def test_get_epss_dict(mock_stringio, mock_csv_reader):
    mock_csv_reader.return_value = [["row1", "row2"], ["row3", "row4"]]

    epss_dict = AddData([]).get_epss_dict("epss_data")

    assert epss_dict == {"row1": "row2", "row3": "row4"}


@patch(
    "devsecops_engine_tools.engine_risk.src.domain.usecases.add_data.AddData.download_epss_data"
)
@patch(
    "devsecops_engine_tools.engine_risk.src.domain.usecases.add_data.AddData.get_epss_dict"
)
def test_add_data(mock_get_epss_dict, mock_download_epss_data):
    mock_get_epss_dict.return_value = {"CVE-2021-1234": "10"}

    findings = [
        Mock(vul_id="CVE-2021-1234", epss_score=0),
        Mock(vul_id="CVE-2021-1235", epss_score=0),
    ]

    updated_findings = AddData(findings).add_data()

    assert updated_findings[0].epss_score == "10"
    assert updated_findings[1].epss_score == 0
