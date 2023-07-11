import json
from devsecops_engine_utilities.settings import DEVSECOPS_ENGINE_UTILITIES_PATH
from devsecops_engine_utilities.defect_dojo.domain.models.product_list import ProductList


def test_product_from_mixin():
    with open(f"{DEVSECOPS_ENGINE_UTILITIES_PATH}/defect_dojo/test/files/response_product.json", "r") as fp:
        data = json.load(fp)
        product_obj = ProductList.from_dict(data)
        print("object", product_obj.results)
        assert product_obj.results[0].name == "test_NU0212001"
        assert product_obj.results[0].description == "test_NU0212001"
        assert product_obj.results[0].created == "2023-06-15T02:11:01.629718Z"
