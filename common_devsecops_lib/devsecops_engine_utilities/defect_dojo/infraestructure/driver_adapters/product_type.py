import requests
import json
from devsecops_engine_utilities.helper.logger_info import MyLogger
from devsecops_engine_utilities.helper.validation_error import ValidationError
from devsecops_engine_utilities.defect_dojo.domain.request_objects.import_scan import ImportScanRequest
from devsecops_engine_utilities.defect_dojo.domain.models.product_type_list import ProductTypeList
from devsecops_engine_utilities.defect_dojo.domain.models.product_type import ProductType
from devsecops_engine_utilities.defect_dojo.infraestructure.driver_adapters.settings.settings import VERIFY_CERTIFICATE

logger = MyLogger.__call__().get_logger()


class ProductTypeRestConsumer:
    def __init__(self, request: ImportScanRequest):
        self.__token = request.token_defect_dojo
        self.__host = request.host_defect_dojo

    def post_product_type(self, request: ImportScanRequest) -> ProductType:
        url = f"{self.__host}/api/v2/product_types/"

        data = json.dumps({"name": request.product_type_name})

        headers = {"Authorization": f"Token {self.__token}", "Content-Type": "application/json"}

        response = requests.request("POST", url, headers=headers, data=data)
        if response.status_code != 201:
            raise ValidationError(response)
        product_type_object = ProductType.from_dict(response.json())
        return product_type_object

    def get_product_types(self, request: ImportScanRequest) -> ProductTypeList:
        url = f"{self.__host}/api/v2/product_types/?name={request.product_type_name}"
        headers = {"Authorization": f"Token {self.__token}"}
        response = requests.request("GET", url, headers=headers, data={}, verify=VERIFY_CERTIFICATE)
        if response.status_code != 200:
            raise ValidationError(response)
        product_type_object = ProductTypeList.from_dict(response.json())
        return product_type_object

    def get_product_type_id(self, id: int):
        url = f"{self.__host}/api/v2/product_types/{id}/"

        headers = {"Authorization": f"Token {self.__token}"}

        response = requests.request("GET", url, headers=headers, data={}, verify=VERIFY_CERTIFICATE)
        if response.status_code != 200:
            raise ValidationError(response)
        logger.info(response)
        product_type_object = ProductTypeList.from_dict(response.json())
        return product_type_object
