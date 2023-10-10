import pytest
from unittest.mock import Mock
from devsecops_engine_utilities.utils.api_error import ApiError
from devsecops_engine_utilities.defect_dojo.test.files.get_response import (
    get_response,
    session_manager_post,
    session_manager_get,
)
from devsecops_engine_utilities.defect_dojo.infraestructure.driver_adapters.product import ProductRestConsumer
from devsecops_engine_utilities.defect_dojo.domain.models.product_list import ProductList
from devsecops_engine_utilities.defect_dojo.domain.models.product import Product
from devsecops_engine_utilities.defect_dojo.domain.request_objects.import_scan import ImportScanRequest


def test_get_product_info_success():
    session_mock = session_manager_get(status_code=200, response_json_file="product_list.json")
    request = ImportScanRequest()
    rest_product = ProductRestConsumer(request, session_mock)
    product_obj = rest_product.get_products(request)
    # Verificar el resultado
    assert isinstance(product_obj, ProductList)
    assert product_obj.count == 2
    assert isinstance(product_obj.results, list)
    assert product_obj.results[0].name == "product name test_NU0212001"
    assert product_obj.results[0].description == "description test"
    assert product_obj.results[0].created == "2023-07-11T13:29:05.245841Z"


def test_get_product_info_failure():
    session_mock = session_manager_get(status_code=500, response_json_file="product_list.json")
    request = ImportScanRequest()
    rest_product = ProductRestConsumer(ImportScanRequest(), session_mock)
    with pytest.raises(ApiError):
        rest_product.get_products(request)


def test_post_product_info_sucessfull():
    session_mock = session_manager_post(status_code=201, mock_response="product.json")
    rest_product = ProductRestConsumer(ImportScanRequest(), session_mock)
    request = ImportScanRequest()
    request.product_name = "NU0212001_product name test_NU0212001"
    response = rest_product.post_product(request, 278)
    assert isinstance(response, Product)
    assert response.id == 278
    assert response.created == "2023-07-11T22:22:51.397136Z"
    assert response.description == "description product"
    assert response.tags == []
    assert isinstance(response.members, list)


def test_post_product_info_failure():
    session_mock = session_manager_post(status_code=500, mock_response="product.json")
    rest_product_type = ProductRestConsumer(ImportScanRequest(), session_mock)
    with pytest.raises(ApiError):
        rest_product_type.post_product(ImportScanRequest(), 278)
