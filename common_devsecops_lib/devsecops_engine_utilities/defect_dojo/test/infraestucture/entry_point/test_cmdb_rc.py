import pytest
from unittest.mock import Mock
from devsecops_engine_utilities.defect_dojo.domain.models.cmdb import Cmdb

from devsecops_engine_utilities.defect_dojo.infraestructure.driver_adapters.cmdb import CmdbRestConsumer

from devsecops_engine_utilities.utils.validation_error import ValidationError


def session_manager(status_code):
    # Mocks
    session_mock = Mock()
    response_mock = Mock()
    response_mock.status_code = status_code
    response_mock.json.return_value = [
        {"name_cmdb": "NU0429001_Test", "product_type_name_cmdb": "software"}]
    session_mock.post.return_value = response_mock
    return session_mock


def test_get_product_info_success():
    session_mock = session_manager(status_code=200)
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
    assert cmdb_object.product_name == "NU0429001_Test"
    assert cmdb_object.product_type_name == "software"


def test_get_product_info_failure():
    session_mock = session_manager(500)
    consumer = CmdbRestConsumer(
        "token12345",
        "http://hosttest.com",
        {"product_name": "name_cmdb", "product_type_name": "product_type_name_cmdb"},
        session_mock,
    )
    with pytest.raises(ValidationError):
        consumer.get_product_info(123)
