from unittest.mock import Mock
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.user_case.product import ProductUserCase
from devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.product import ProductRestConsumer
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.models.product import Product
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.models.product_list import ProductList
from requests import Response


def test_execute_product_get():
    mock_rest_product = Mock()
    # Creation mocks, get and close
    mock_rest_product.get_products.return_value = ProductList(count=1, results=[Product(id=1), Product(id=2)])
    response = Response()
    response.status_code = 200
    mock_rest_product.get_products.return_value = response
    uc = ProductUserCase(mock_rest_product)
    response = uc.execute({"codeapp": "name"})
    assert response.status_code == 200
