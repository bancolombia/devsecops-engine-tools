from devsecops_engine_tools.engine_utilities.utils.api_error import ApiError
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.request_objects.import_scan import ImportScanRequest
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.models.product import Product
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.models.product_list import ProductList
from devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.settings.settings import VERIFY_CERTIFICATE
from devsecops_engine_tools.engine_utilities.utils.session_manager import SessionManager
from devsecops_engine_tools.engine_utilities.settings import SETTING_LOGGER

logger = MyLogger.__call__(**SETTING_LOGGER).get_logger()


class ProductRestConsumer:
    def __init__(self, request: ImportScanRequest, session: SessionManager):
        self.__token = request.token_defect_dojo
        self.__host = request.host_defect_dojo
        self.__session = session._instance

    def get_products(self, request: ImportScanRequest) -> ProductList:
        url = f"{self.__host}/api/v2/products/?name={request.code_app}"
        headers = {"Authorization": f"Token {self.__token}", "Content-Type": "application/json"}
        try:
            response = self.__session.get(url, headers=headers, data={}, verify=VERIFY_CERTIFICATE)
            if response.status_code != 200:
                raise ApiError(response.json())
            products_object = ProductList.from_dict(response.json())
        except Exception as e:
            logger.error(f"from dict product: {e}")
            raise ApiError(e)
        return products_object

    def post_product(self, request: ImportScanRequest, product_type_id: int) -> Product:
        url = f"{self.__host}/api/v2/products/"

        data = {
            "name": request.product_name,
            "description": "AREA RESPONSABLE TI: " + request.product_description.upper(),
            "enable_full_risk_acceptance": True,
            "prod_type": product_type_id,
        }
        headers = {"Authorization": f"Token {self.__token}"}
        try:
            response = self.__session.post(url, headers=headers, data=data, verify=VERIFY_CERTIFICATE)
            if response.status_code != 201:
                raise ApiError(response.json())
            product_object = Product.from_dict(response.json())
        except Exception as e:
            logger.error(f"form dict product: {response.json()}")
            raise ApiError(e)
        return product_object
