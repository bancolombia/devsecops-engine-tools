import pytest
import json
from unittest.mock import Mock
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.models.cmdb import Cmdb
from devsecops_engine_tools.engine_utilities.defect_dojo.test.files.get_response import session_manager_post
from devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.cmdb import CmdbRestConsumer
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.request_objects.import_scan import ImportScanRequest
from devsecops_engine_tools.engine_utilities.utils.api_error import ApiError


def test_get_product_info_success():
    request = ImportScanRequest()
    request.code_app = "123"
    request.cmdb_request_response = {
        "METHOD": "POST",
        "HEADERS": {"Content-Type": "application/json"},
        "RESPONSE": [0]
    }
    session_mock = session_manager_post(
        status_code=200, mock_response=[{"name_cmdb": "NU1245_Test", "product_type_name_cmdb": "software"}]
    )
    # Crear una instancia de CmdbRestConsumer con los mocks
    consumer = CmdbRestConsumer(
        "token12345",
        "http://hosttest.com",
        {"product_name": "name_cmdb", "product_type_name": "product_type_name_cmdb"},
        session_mock,
    )

    # Llamar al método bajo prueba
    cmdb_object = consumer.get_product_info(request)

    # Verificar el resultado
    assert isinstance(cmdb_object, Cmdb)
    assert cmdb_object.product_name == "NU1245_Test"
    assert cmdb_object.product_type_name == "software"


def test_get_product_info_failure():
    request = ImportScanRequest()
    request.code_app = "123"
    request.cmdb_request_response = {
        "METHOD": "POST",
        "HEADERS": {"Content-Type": "application/json"}
    }
    session_mock = session_manager_post(status_code=500, mock_response={"Message": "Error mock"})
    consumer = CmdbRestConsumer(
        "token12345",
        "http://hosttest.com",
        {"product_name": "name_cmdb", "product_type_name": "product_type_name_cmdb"},
        session_mock,
    )

    response = consumer.get_product_info(request)
    assert response.product_type_name == "ORPHAN_PRODUCT_TYPE"


def test_get_product_info_unsupported_method():
    request = ImportScanRequest()
    request.code_app = "123"
    request.cmdb_request_response = {
        "METHOD": "PUT",
        "HEADERS": {"Content-Type": "application/json"}
    }
    session_mock = session_manager_post(status_code=500, mock_response={"Message": "Error mock"})
    consumer = CmdbRestConsumer(
        "token12345",
        "http://hosttest.com",
        {"product_name": "name_cmdb", "product_type_name": "product_type_name_cmdb"},
        session_mock,
    )

    with pytest.raises(ValueError):
        consumer.get_product_info(request)


def test_process_response_success():
    response = Mock()
    response.status_code = 200
    response.json.return_value = [{"name_cmdb": "NU1245_Test", "product_type_name_cmdb": "software"}]
    consumer = CmdbRestConsumer(
        "token12345",
        "http://hosttest.com",
        {"product_name": "name_cmdb", "product_type_name": "product_type_name_cmdb"},
        Mock(),
    )

    cmdb_object = consumer.process_response(response, [0], Cmdb(), "123")

    assert isinstance(cmdb_object, Cmdb)
    assert cmdb_object.product_name == "NU1245_Test"
    assert cmdb_object.product_type_name == "software"


def test_initialize_cmdb_object():
    consumer = CmdbRestConsumer(
        "token12345",
        "http://hosttest.com",
        {"product_name": "name_cmdb", "product_type_name": "product_type_name_cmdb"},
        Mock(),
    )

    request = ImportScanRequest(code_app="TEST123")

    cmdb_object = consumer.initialize_cmdb_object(request)

    expected_cmdb = Cmdb(
        product_type_name="ORPHAN_PRODUCT_TYPE",
        product_name="TEST123_Product",
        tag_product="ORPHAN",
        product_description="Orphan Product Description",
        codigo_app="TEST123",
    )
    assert cmdb_object == expected_cmdb


def test_mapping_cmdb_valid_data():
    consumer = CmdbRestConsumer(
        "token12345",
        "http://hosttest.com",
        {"product_name": "name_cmdb", "product_type_name": "product_type_name_cmdb"},
        Mock(),
    )

    data = {"name_cmdb": "NU1245_Test", "product_type_name_cmdb": "software"}

    result = consumer.mapping_cmdb(data)

    expected = {"product_name": "NU1245_Test", "product_type_name": "software"}
    assert result == expected


def test_mapping_cmdb_missing_data():
    consumer = CmdbRestConsumer(
        "token12345",
        "http://hosttest.com",
        {"product_name": "name_cmdb", "product_type_name": "product_type_name_cmdb"},
        Mock(),
    )

    data = {"name_cmdb": "NU1245_Test"}

    result = consumer.mapping_cmdb(data)

    expected = {"product_name": "NU1245_Test", "product_type_name": ""}
    assert result == expected


def test_get_nested_data_with_valid_keys():
    consumer = CmdbRestConsumer(
        "token12345",
        "http://hosttest.com",
        {"product_name": "name_cmdb", "product_type_name": "product_type_name_cmdb"},
        Mock(),
    )
    response_mock = Mock()
    response_mock.json.return_value = {"name_cmdb": "NU1245_Test", "product_type_name_cmdb": "software"}
    keys = ["name_cmdb"]

    result = consumer.get_nested_data(response_mock, keys)

    assert result == "NU1245_Test"
    

def test_get_nested_data_with_invalid_keys():
    consumer = CmdbRestConsumer(
        "token12345",
        "http://hosttest.com",
        {"product_name": "name_cmdb", "product_type_name": "product_type_name_cmdb"},
        Mock(),
    )

    response_mock = Mock()
    response_mock.json.return_value = {"name_cmdb": "NU1245_Test", "product_type_name_cmdb": "software"}
    keys = ["name_cmdb", "product_type_name_cmdb", "invalid_key"]

    with pytest.raises(KeyError):
        consumer.get_nested_data(response_mock, keys)


def test_prepare_headers_with_tokenvalue():
    consumer = CmdbRestConsumer(
        "token12345",
        "http://hosttest.com",
        {"product_name": "name_cmdb", "product_type_name": "product_type_name_cmdb"},
        Mock(),
    )

    headers = {"Authorization": "tokenvalue", "Content-Type": "application/json"}

    result = consumer.prepare_headers(headers)

    expected = {"Authorization": "token12345", "Content-Type": "application/json"}
    assert result == expected


def test_replace_placeholders_valid_replacement():
    consumer = CmdbRestConsumer(
        "token12345",
        "http://hosttest.com",
        {"product_name": "name_cmdb", "product_type_name": "product_type_name_cmdb"},
        Mock(),
    )

    data = '{"key": "codappvalue"}'
    replacements = "new_value"

    # Act
    result = consumer.replace_placeholders(data, replacements)

    # Assert
    expected = {"key": "new_value"}
    assert result == expected