from unittest.mock import MagicMock
from devsecops_engine_tools.engine_risk.src.domain.usecases.add_data import AddData


def test_init():
    add_epss_gateway = MagicMock()
    findings = MagicMock()

    add_data = AddData(add_epss_gateway, findings)

    assert add_data.add_epss_gateway == add_epss_gateway
    assert add_data.findings == findings


def test_process():
    add_epss_gateway = MagicMock()
    findings = MagicMock()
    add_data = AddData(add_epss_gateway, findings)
    add_epss_gateway.add_epss_data.return_value = "findings"

    result = add_data.process()

    assert result == "findings"
    add_epss_gateway.add_epss_data.assert_called_once_with(findings)
