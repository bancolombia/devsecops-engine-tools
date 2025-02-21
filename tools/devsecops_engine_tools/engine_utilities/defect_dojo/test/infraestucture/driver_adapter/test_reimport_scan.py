import json
import pytest
from unittest.mock import Mock
from devsecops_engine_tools.engine_utilities.utils.api_error import ApiError
from devsecops_engine_tools.engine_utilities.defect_dojo.test.files.get_response import session_manager_post
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.request_objects.import_scan import ImportScanRequest
from devsecops_engine_tools.engine_utilities.settings import DEVSECOPS_ENGINE_UTILITIES_PATH
from devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.reimport_scan import ReimportScanRestConsumer 


def test_post_reimport_scan_info_sucessfull():
    session_mock = session_manager_post(status_code=201, mock_response="import_scan.json")
    request = ImportScanRequest()
    rest_reimport_scan = ReimportScanRestConsumer(request, session_mock)
    response = rest_reimport_scan.reimport_scan_api(request)
    assert isinstance(response, ImportScanRequest)
    assert response.product_type_name == "defect-dojo"

    with open(f"{DEVSECOPS_ENGINE_UTILITIES_PATH}/defect_dojo/test/files/import_scan.json", "r") as fp:
        response = rest_reimport_scan.reimport_scan(request, fp)
    assert response.json()["product_type_name"] == "defect-dojo"


def test_post_reimport_scan_info_sucessfull():
    session_mock = session_manager_post(status_code=201, mock_response="import_scan.json")
    request = ImportScanRequest()
    rest_reimport_scan = ReimportScanRestConsumer(request, session_mock)
    with open(f"{DEVSECOPS_ENGINE_UTILITIES_PATH}/defect_dojo/test/files/import_scan.json", "r") as fp:
        response = rest_reimport_scan.reimport_scan(request, fp)
        assert isinstance(response, ImportScanRequest)
        assert response.product_type_name == "defect-dojo"


def test_post_reimport_scan_info_failure():
    session_mock = session_manager_post(status_code=500, mock_response="engagement.json")
    file = None
    request = ImportScanRequest()
    rest_reimport_scan = ReimportScanRestConsumer(
        request,
        session_mock,
    )
    with pytest.raises(ApiError):
        rest_reimport_scan.reimport_scan(request, file)


def test_post_reimport_scan_api_info_failure():
    session_mock = session_manager_post(status_code=500, mock_response="engagement.json")
    request = ImportScanRequest()
    rest_import_scan = ReimportScanRestConsumer(
        request,
        session_mock,
    )
    with pytest.raises(ApiError):
        rest_import_scan.reimport_scan_api(request)


def test_post_reimport_scan_info_sucessfull():
    session_mock = session_manager_post(status_code=201, mock_response="import_scan.json")
    request = ImportScanRequest()
    rest_import_scan = ReimportScanRestConsumer(request, session_mock)
    response = rest_import_scan.reimport_scan_api(request)
    assert isinstance(response, ImportScanRequest)
    assert response.product_type_name == "defect-dojo"