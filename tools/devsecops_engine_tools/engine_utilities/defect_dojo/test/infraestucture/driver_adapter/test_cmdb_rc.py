import pytest
from unittest.mock import Mock
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.models.cmdb import Cmdb
from devsecops_engine_tools.engine_utilities.defect_dojo.test.files.get_response import session_manager_post
from devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.cmdb import CmdbRestConsumer
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.request_objects.import_scan import ImportScanRequest
from devsecops_engine_tools.engine_utilities.utils.api_error import ApiError


def test_get_product_info_success():
    request = ImportScanRequest()
    request.code_app = "123"
    request.product_name = "test_product_name"
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
    request.product_name = "test_product_name"
    session_mock = session_manager_post(status_code=500, mock_response={"Message": "Error mock"})
    consumer = CmdbRestConsumer(
        "token12345",
        "http://hosttest.com",
        {"product_name": "name_cmdb", "product_type_name": "product_type_name_cmdb"},
        session_mock,
    )
    
    response = consumer.get_product_info(request)
    assert response.product_type_name == "ORPHAN_PRODUCT_TYPE"
