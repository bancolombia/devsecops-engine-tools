import pytest
from unittest.mock import Mock
from devsecops_engine_utilities.defect_dojo.domain.models.cmdb import Cmdb
from devsecops_engine_utilities.defect_dojo.test.files.get_response import session_manager_post
from devsecops_engine_utilities.defect_dojo.infraestructure.driver_adapters.cmdb import CmdbRestConsumer
from devsecops_engine_utilities.utils.api_error import ApiError


def test_get_product_info_success():
    session_mock = session_manager_post(
        status_code=200, mock_response=[{"name_cmdb": "NU12345_Test", "product_type_name_cmdb": "software"}]
    )
    # Crear una instancia de CmdbRestConsumer con los mocks
    consumer = CmdbRestConsumer(
        "token12345",
        "http://hosttest.com",
        {"product_name": "name_cmdb", "product_type_name": "product_type_name_cmdb"},
        session_mock,
    )

    # Llamar al método bajo prueba
    cmdb_object = consumer.get_product_info(123)

    # Verificar el resultado
    assert isinstance(cmdb_object, Cmdb)
    assert cmdb_object.product_name == "NU12345_Test"
    assert cmdb_object.product_type_name == "software"


def test_get_product_info_failure():
    session_mock = session_manager_post(status_code=500, mock_response={"Message": "Error mock"})
    consumer = CmdbRestConsumer(
        "token12345",
        "http://hosttest.com",
        {"product_name": "name_cmdb", "product_type_name": "product_type_name_cmdb"},
        session_mock,
    )
    with pytest.raises(ApiError):
        consumer.get_product_info(123)
