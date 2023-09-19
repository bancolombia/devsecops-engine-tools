import json
import pytest
from unittest.mock import Mock
from common_devsecops_lib.devsecops_engine_utilities.utils.api_error import ApiError
from devsecops_engine_utilities.defect_dojo.test.files.get_response import session_manager_post
from devsecops_engine_utilities.defect_dojo.domain.request_objects.import_scan import ImportScanRequest
from devsecops_engine_utilities.settings import DEVSECOPS_ENGINE_UTILITIES_PATH
from devsecops_engine_utilities.defect_dojo.infraestructure.driver_adapters.import_scan import ImportScanRestConsumer


def test_post_import_scan_info_sucessfull():
    session_mock = session_manager_post(status_code=201, response_json_file="import_scan.json")
    request = ImportScanRequest()
    rest_import_scan = ImportScanRestConsumer(request, session_mock)
    response = rest_import_scan.import_scan_api(request)
    assert isinstance(response, ImportScanRequest)
    assert response.product_type_name == "defect-dojo"

    with open(f"{DEVSECOPS_ENGINE_UTILITIES_PATH}/defect_dojo/test/files/import_scan.json", "r") as fp:
        response = rest_import_scan.import_scan(request, fp)
    assert response.json()["product_type_name"] == "defect-dojo"


def test_post_import_scan_info_sucessfull():
    session_mock = session_manager_post(status_code=201, response_json_file="import_scan.json")
    request = ImportScanRequest()
    rest_import_scan = ImportScanRestConsumer(request, session_mock)
    with open(f"{DEVSECOPS_ENGINE_UTILITIES_PATH}/defect_dojo/test/files/import_scan.json", "r") as fp:
        response = rest_import_scan.import_scan(request, fp)
        assert isinstance(response, ImportScanRequest)
        assert response.product_type_name == "defect-dojo"


def test_post_import_scan_api_info_failure():
    session_mock = session_manager_post(status_code=500, response_json_file="engagement.json")
    request = ImportScanRequest()
    rest_import_scan = ImportScanRestConsumer(
        request,
        session_mock,
    )
    with pytest.raises(ApiError):
        rest_import_scan.import_scan_api(request)


def test_post_import_scan_info_failure():
    session_mock = session_manager_post(status_code=500, response_json_file="engagement.json")
    file = None
    request = ImportScanRequest()
    rest_import_scan = ImportScanRestConsumer(
        request,
        session_mock,
    )
    with pytest.raises(ApiError):
        rest_import_scan.import_scan(request, file)
