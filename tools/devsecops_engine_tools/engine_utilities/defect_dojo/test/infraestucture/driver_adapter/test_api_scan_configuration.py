import pytest
from unittest.mock import Mock
from devsecops_engine_tools.engine_utilities.utils.api_error import ApiError
from devsecops_engine_tools.engine_utilities.defect_dojo.test.files.get_response import (
    get_response,
    session_manager_post,
    session_manager_get,
)
from devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.scan_configurations import (
    ScanConfigrationRestConsumer,
)
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.models.scan_configuration import (
    ScanConfigurationList,
    ScanConfiguration,
)
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.models.product import Product
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.request_objects.import_scan import ImportScanRequest


def test_get_scan_configurations_info_success():
    session_mock = session_manager_get(status_code=200, response_json_file="scan_configuration_list.json")
    request = ImportScanRequest()
    rest_scan_configurations = ScanConfigrationRestConsumer(request, session_mock)
    scan_configurations_list = rest_scan_configurations.get_api_scan_configuration(request)
    # Verificar el resultado
    assert isinstance(scan_configurations_list, ScanConfigurationList)
    assert isinstance(scan_configurations_list.results[0].id, int)
    assert scan_configurations_list.count == 1
    assert isinstance(scan_configurations_list.results, list)
    assert scan_configurations_list.results[0].service_key_1 == "defect-dojo"
    assert isinstance(scan_configurations_list.results[0].tool_configuration, int)
    assert scan_configurations_list.results[0].tool_configuration == 1


def test_get_scan_configrations_info_failure():
    session_mock = session_manager_get(status_code=500, response_json_file="scan_configuration_list.json")
    request = ImportScanRequest()
    rest_scan_configuration = ScanConfigrationRestConsumer(request, session_mock)
    with pytest.raises(ApiError):
        rest_scan_configuration.get_api_scan_configuration(request)


def test_post_scan_configuration_info_sucessfull():
    session_mock = session_manager_post(status_code=201, mock_response="scan_configuration.json")
    request = ImportScanRequest()
    rest_scan_configurations = ScanConfigrationRestConsumer(request, session_mock)
    # The engagement must be equal to service_key
    request.engagement_name = "defect-dojo"
    response = rest_scan_configurations.post_api_scan_configuration(request, 1, 1)
    assert isinstance(response, ScanConfiguration)
    assert response.id == 412
    assert response.service_key_1 == "defect-dojo"
    assert response.product == 510
    assert response.tool_configuration == 1


def test_post_product_info_failure():
    session_mock = session_manager_post(status_code=500, mock_response="scan_configuration.json")
    rest_scan_configuration = ScanConfigrationRestConsumer(ImportScanRequest(), session_mock)
    with pytest.raises(ApiError):
        rest_scan_configuration.post_api_scan_configuration(ImportScanRequest(), 1, 1)
