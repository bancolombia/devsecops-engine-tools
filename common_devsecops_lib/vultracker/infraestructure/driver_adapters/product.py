import requests
from devsecops_lib.helper.logger_info import MyLogger
from devsecops_lib.helper.validation_error import ValidationError
from devsecops_lib.vultracker.domain.request_objects.import_scan import ImportScanRequest
from devsecops_lib.vultracker.domain.models.product import Product
from devsecops_lib.vultracker.domain.models.product_list import ProductList
from devsecops_lib.vultracker.infraestructure.driver_adapters.settings.settings import VERIFY_CERTIFICATE
logger = MyLogger.__call__().get_logger()


class ProductRestConsumer:

    def __init__(self, request: ImportScanRequest):
        self.__token = request.token_vultracker
        self.__host = request.host_vultracker

    def get_products(self, request: ImportScanRequest) -> ProductList:
        url = f"{self.__host}/api/v2/products/?name={request.product_name}"
        headers = {
            "Authorization": f"Token {self.__token}",
            "Content-Type": "application/json"
        }
        response = requests.request("GET", url,
                                    headers=headers,
                                    data={},
                                    verify=VERIFY_CERTIFICATE)
        if response.status_code != 200:
            logger.info(response)
            raise ValidationError(response.json())
        products_object = ProductList.from_dict(response.json())
        return products_object

    def post_product(self, request: ImportScanRequest, product_type_id: int) -> Product:

        url = f"{self.__host}/api/v2/products/"

        data = {
            "name": request.product_name,
            "description": request.product_name,
            "prod_type": product_type_id
            }

        headers = {
            "Authorization": f"Token {self.__token}"
        }
        response = requests.request("POST", url,
                                    headers=headers,
                                    data=data,
                                    verify=VERIFY_CERTIFICATE)
        if response.status_code != 201:
            logger.info(response)
            raise ValidationError(response.json())
        product_object = Product.from_dict(response.json())
        return product_object
