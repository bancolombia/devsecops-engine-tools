import pytest
from unittest.mock import Mock
from devsecops_engine_utilities.utils.api_error import ApiError
from devsecops_engine_utilities.defect_dojo.domain.user_case.finding import FindingUserCase, FindingGetUserCase
from devsecops_engine_utilities.utils.session_manager import SessionManager
from devsecops_engine_utilities.defect_dojo.infraestructure.driver_adapters.finding import FindingRestConsumer
from devsecops_engine_utilities.defect_dojo.domain.models.finding import Finding, FindingList
from requests import Response


def test_execute_finding_close():
    mock_rest_finding = Mock()
    # Creation mocks, get and close
    mock_rest_finding.get.return_value = FindingList(count=1, results=[Finding(id=1), Finding(id=2)])
    response = Response()
    response.status_code = 200
    mock_rest_finding.close.return_value = response
    uc = FindingUserCase(mock_rest_finding)
    response = uc.execute({"active": "true"})
    assert response.status_code == 200


def test_execute_finding_get():
    mock_rest_finding = Mock()
    # Creation mocks, get and close
    mock_rest_finding.get.return_value = FindingList(count=1, results=[Finding(id=1), Finding(id=2)])
    response = Response()
    response.status_code = 200
    mock_rest_finding.get.return_value = response
    uc = FindingGetUserCase(mock_rest_finding)
    response = uc.execute({"active": "true"})
    assert response.status_code == 200
