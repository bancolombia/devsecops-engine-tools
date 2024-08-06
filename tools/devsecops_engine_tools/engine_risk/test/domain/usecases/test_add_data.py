from unittest.mock import MagicMock, patch
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
