from unittest.mock import MagicMock, patch

from devsecops_engine_tools.engine_utilities.defect_dojo.applications.product import (
    Product,
)



@patch(
    "devsecops_engine_tools.engine_utilities.defect_dojo.applications.product.ProductRestConsumer"
)
def test_get_products(mock_product_rest_consumer):
    mock_product_rest_consumer.return_value.get_products.return_value = (
        "response"
    )
    session = MagicMock()
    request = MagicMock()
    assert Product.get_product(session, request) == "response"



@patch(
    "devsecops_engine_tools.engine_utilities.defect_dojo.applications.product.ProductRestConsumer"
)
def test_get_products_raises_api_error(
    mock_product_rest_consumer
):
    mock_product_rest_consumer.return_value.get_products.side_effect = Exception(
        "error"
    )
    session = MagicMock()
    request = MagicMock()
    try:
        Product.get_product(session, request)
    except Exception as e:
        assert str(e) == "error"
