import pytest
from unittest.mock import Mock
from devsecops_engine_utilities.defect_dojo.domain.models.cmdb import Cmdb
from devsecops_engine_utilities.utils.validation_error import ValidationError
from devsecops_engine_utilities.defect_dojo.test.files.get_response import (
    get_response,
    session_manager_post,
    session_manager_get,
)
from devsecops_engine_utilities.defect_dojo.infraestructure.driver_adapters.engagement import EngagementRestConsumer


def test_get_engagement_info_success():
    session_mock = session_manager_get(status_code=200, response_json_file="engagement_list.json")
    # Crear una instancia de CmdbRestConsumer con los mocks
    rest_engagement = EngagementRestConsumer(
        "token12345",
        "http://hosttest.com",
        session_mock,
    )

    # Llamar al método bajo prueba
    engagement_obj = rest_engagement.get_engagement("NU0212001_test_engagement_name")

    # Verificar el resultado
    assert isinstance(engagement_obj, dict)
    assert engagement_obj["count"] == 1
    assert isinstance(engagement_obj["results"], list)
    assert engagement_obj["results"][0]["name"] == "NU0212001_test_engagement_name"


def test_get_engagement_info_failure():
    session_mock = session_manager_get(status_code=500, response_json_file="engagement_list.json")
    rest_engagement = EngagementRestConsumer(
        "token12345",
        "http://hosttest.com",
        session_mock,
    )
    with pytest.raises(ValidationError):
        rest_engagement.get_engagement("NU0212001_test_engagement_name")


def test_post_engagement_info_sucessfull():
    session_mock = session_manager_post(status_code=201, response_json_file="engagement.json")
    rest_engagement = EngagementRestConsumer(
        "token12345",
        "http://hosttest.com",
        session_mock,
    )
    response = rest_engagement.post_engagement(engagement_name="NU0212001_test_engagement_name", product_id=195)
    assert response["id"] == 195


def test_post_engagement_info_failure():
    session_mock = session_manager_post(status_code=500, response_json_file="engagement.json")
    rest_engagement = EngagementRestConsumer(
        "token12345",
        "http://hosttest.com",
        session_mock,
    )
    with pytest.raises(ValidationError):
        rest_engagement.get_engagement("NU0212001_test_engagement_name")
