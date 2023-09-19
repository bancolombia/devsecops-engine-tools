import pytest
from unittest.mock import Mock
from devsecops_engine_utilities.defect_dojo.domain.models.cmdb import Cmdb
from common_devsecops_lib.devsecops_engine_utilities.utils.api_error import ApiError
from devsecops_engine_utilities.defect_dojo.test.files.get_response import (
    get_response,
    session_manager_post,
    session_manager_get,
)
from devsecops_engine_utilities.defect_dojo.domain.models.product_type_list import ProductTypeList
from devsecops_engine_utilities.defect_dojo.domain.models.product_type import ProductType
from devsecops_engine_utilities.defect_dojo.infraestructure.driver_adapters.product_type import ProductTypeRestConsumer
from devsecops_engine_utilities.defect_dojo.domain.request_objects.import_scan import ImportScanRequest


def test_get_product_type_info_success():
    session_mock = session_manager_get(status_code=200, response_json_file="product_type_list.json")
    rest_product_type = ProductTypeRestConsumer(ImportScanRequest(), session_mock)
    product_type_obj = rest_product_type.get_product_types("product_type name test")

    # Verificar el resultado
    assert isinstance(product_type_obj, ProductTypeList)
    assert product_type_obj.count == 1
    assert isinstance(product_type_obj.results, list)
    assert product_type_obj.results[0].name == "product_type name test"
    assert product_type_obj.results[0].id == 162


def test_get_product_type_info_failure():
    session_mock = session_manager_get(status_code=500, response_json_file="product_type_list.json")
    rest_product_type = ProductTypeRestConsumer(ImportScanRequest(), session_mock)
    with pytest.raises(ApiError):
        rest_product_type.get_product_types("product_type name test")


def test_post_product_type_info_sucessfull():
    session_mock = session_manager_post(status_code=201, response_json_file="product_type.json")
    rest_product_type = ProductTypeRestConsumer(ImportScanRequest(), session_mock)
    response = rest_product_type.post_product_type("product_type name test")
    assert isinstance(response, ProductType)
    assert response.id == 163
    assert response.updated == "2023-07-11T16:44:08.397702Z"
    assert isinstance(response.members, list)


def test_post_product_type_info_failure():
    session_mock = session_manager_post(status_code=500, response_json_file="product_type.json")
    rest_product_type = ProductTypeRestConsumer(ImportScanRequest(), session_mock)
    with pytest.raises(ApiError):
        rest_product_type.post_product_type("NU0212001_test_engagement_name")
