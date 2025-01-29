import json
from devsecops_engine_tools.engine_utilities.utils.api_error import ApiError
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.request_objects.import_scan import ImportScanRequest
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.models.product_type_list import ProductTypeList
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.models.product_type import ProductType
from devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.settings.settings import VERIFY_CERTIFICATE
from devsecops_engine_tools.engine_utilities.utils.session_manager import SessionManager
from devsecops_engine_tools.engine_utilities.settings import SETTING_LOGGER

logger = MyLogger.__call__(**SETTING_LOGGER).get_logger()


class ProductTypeRestConsumer:
    def __init__(self, request: ImportScanRequest, session: SessionManager):
        self.__token = request.token_defect_dojo
        self.__host = request.host_defect_dojo
        self.__session = session._instance

    def post_product_type(self, product_type_name: str) -> ProductType:
        url = f"{self.__host}/api/v2/product_types/"
        data = json.dumps({"name": product_type_name})
        headers = {"Authorization": f"Token {self.__token}", "Content-Type": "application/json"}
        try:
            response = self.__session.post(url, headers=headers, data=data, verify=VERIFY_CERTIFICATE)
            if response.status_code != 201:
                raise ApiError(response.json())
            product_type_object = ProductType.from_dict(response.json())
        except Exception as e:
            log = f"from dict product_type: {response.json}"
            logger.error(log)
            raise ApiError(e)
        return product_type_object

    def get_product_types(self, product_type_name: str) -> ProductTypeList:
        url = f"{self.__host}/api/v2/product_types/?name={product_type_name}"
        headers = {"Authorization": f"Token {self.__token}"}
        try:
            response = self.__session.get(url, headers=headers, data={}, verify=VERIFY_CERTIFICATE)
            if response.status_code != 200:
                raise ApiError(response.json())
            product_type_object = ProductTypeList.from_dict(response.json())
        except Exception as e:
            raise ApiError(e)
        return product_type_object

    def get_product_type_id(self, id: int):
        url = f"{self.__host}/api/v2/product_types/{id}/"

        headers = {"Authorization": f"Token {self.__token}"}
        try:
            response = self.__session.get(url, headers=headers, data={}, verify=VERIFY_CERTIFICATE)
            if response.status_code != 200:
                raise ApiError(response.json())
            logger.info(response)
            product_type_object = ProductType.from_dict(response.json())
        except Exception as e:
            raise ApiError(e)
        return product_type_object
