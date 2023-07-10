import requests
from devsecops_engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_utilities.utils.validation_error import ValidationError
from devsecops_engine_utilities.defect_dojo.domain.request_objects.import_scan import ImportScanRequest
from devsecops_engine_utilities.defect_dojo.domain.models.product import Product
from devsecops_engine_utilities.defect_dojo.domain.models.product_list import ProductList
from devsecops_engine_utilities.defect_dojo.infraestructure.driver_adapters.settings.settings import VERIFY_CERTIFICATE

logger = MyLogger.__call__().get_logger()


class ProductRestConsumer:
    def __init__(self, request: ImportScanRequest):
        self.__token = request.token_defect_dojo
        self.__host = request.host_defect_dojo

    def get_products(self, request: ImportScanRequest) -> ProductList:
        url = f"{self.__host}/api/v2/products/?name={request.product_name}"
        headers = {"Authorization": f"Token {self.__token}", "Content-Type": "application/json"}
        response = requests.request("GET", url, headers=headers, data={}, verify=VERIFY_CERTIFICATE)
        if response.status_code != 200:
            raise ValidationError(response)
        products_object = ProductList.from_dict(response.json())
        return products_object

    def post_product(self, request: ImportScanRequest, product_type_id: int) -> Product:
        url = f"{self.__host}/api/v2/products/"

        data = {"name": request.product_name, "description": request.product_name, "prod_type": product_type_id}

        headers = {"Authorization": f"Token {self.__token}"}
        response = requests.request("POST", url, headers=headers, data=data, verify=VERIFY_CERTIFICATE)
        print(url)
        print(data)
        print(self.__token)
        if response.status_code != 201:
            raise ValidationError(response)
        product_object = Product.from_dict(response.json())
        return product_object
