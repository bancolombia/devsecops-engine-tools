# import pytest
# from unittest.mock import Mock
# from devsecops_engine_utilities.defect_dojo.domain.models.cmdb import Cmdb
# from devsecops_engine_utilities.defect_dojo.infraestructure.driver_adapters.cmdb import (
#     CmdbRestConsumer,
# )
# from devsecops_engine_utilities.utils.validation_error import ValidationError
# from devsecops_engine_utilities.defect_dojo.test.files.get_response import get_response
# from devsecops_engine_utilities.defect_dojo.infraestructure.driver_adapters.engagement import EngagementRestConsumer

# def session_manager(status_code):
#     # Mocks
#     session_mock = Mock()
#     response_mock_get = Mock()
#     response_mock_get.status_code = status_code
#     response_mock_get.json.return_value = get_response("product_types.json")
#     # mocke method post
#     response_mock_post = Mock()
#     response_mock_post.status_code = status_code
#     response_mock_post.json.return_value = get_response("product_types.json")["results"][0]
#     # mock method get y post
#     session_mock.get.return_value = response_mock_get
#     session_mock.post.return_value = response_mock_post
#     return session_mock


# def test_get_engagement_info_success():
#     session_mock = session_manager(status_code=200)
#     # Crear una instancia de CmdbRestConsumer con los mocks
#     rest_engagement = EngagementRestConsumer(
#         "token12345",
#         "http://hosttest.com",
#         session_mock,
#     )

#     # Llamar al método bajo prueba
#     engagement_obj = rest_engagement.get_engagement("NU0212001_test_engagement_name")

#     # Verificar el resultado
#     assert isinstance(engagement_obj, dict)
#     print("debug", engagement_obj)
#     assert engagement_obj["count"] == 1
#     assert isinstance(engagement_obj["results"], list)
#     assert engagement_obj["results"][0]["name"] == "NU0212001_test_engagement_name"


# def test_get_product_info_failure():
#     session_mock = session_manager(500)
#     consumer = CmdbRestConsumer(
#         "token12345",
#         "http://hosttest.com",
#         {"product_name": "name_cmdb", "product_type_name": "product_type_name_cmdb"},
#         session_mock,
#     )
#     with pytest.raises(ValidationError):
#         consumer.get_product_info(123)
