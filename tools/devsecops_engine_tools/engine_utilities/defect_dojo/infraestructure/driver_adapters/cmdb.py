import json
import ast
from devsecops_engine_tools.engine_utilities.utils.api_error import ApiError
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.models.cmdb import Cmdb
from devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.settings.settings import VERIFY_CERTIFICATE
from devsecops_engine_tools.engine_utilities.utils.session_manager import SessionManager
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.request_objects.import_scan import ImportScanRequest
from devsecops_engine_tools.engine_utilities.settings import SETTING_LOGGER

logger = MyLogger.__call__(**SETTING_LOGGER).get_logger()


class CmdbRestConsumer:
    def __init__(self, token: str, host: str, mapping_cmdb: dict, session: SessionManager) -> None:
        self.__token = token
        self.__host = host
        self.__mapping_cmdb = mapping_cmdb
        self.__session = session._instance

    def get_product_info(self, request: ImportScanRequest) -> Cmdb:
        method = request.cmdb_request_response.get("METHOD")
        headers = self.prepare_headers(request.cmdb_request_response.get("HEADERS"))
        response_format = request.cmdb_request_response.get("RESPONSE")

        if method not in ["GET", "POST"]:
            raise ValueError(f"Unsupported method: {method}")
        
        return self.handle_request(method, headers, request, response_format)

    def handle_request(self, method, headers, request: ImportScanRequest, response_format) -> Cmdb:
        cmdb_object = self.initialize_cmdb_object(request)

        try:
            if method == "GET":
                params = self.replace_placeholders(
                    request.cmdb_request_response.get("PARAMS", {}),
                    request.code_app
                )
                response = self.__session.get(self.__host, headers=headers, params=params, verify=VERIFY_CERTIFICATE)
            elif method == "POST":
                body = self.replace_placeholders(
                    request.cmdb_request_response.get("BODY", {}),
                    request.code_app
                )
                body_json = json.dumps(body)
                response = self.__session.post(self.__host, headers=headers, data=body_json, verify=VERIFY_CERTIFICATE)

            return self.process_response(response, response_format, cmdb_object, request.code_app)
        except Exception as e:
            logger.warning(e)
            return cmdb_object

    def process_response(self, response, response_format, cmdb_object, code_app) -> Cmdb:
        if response.status_code != 200:
            logger.warning(response)
            raise ApiError(f"Error querying cmdb: {response.reason}")
        
        if response.json() == []:
            logger.warning(f"Engagement: {code_app} not found")
            return cmdb_object  # Producto es Orphan

        data = self.get_nested_data(response, response_format)
        data_map = self.mapping_cmdb(data)
        logger.info(data_map)
        cmdb_object = Cmdb.from_dict(data_map)
        cmdb_object.codigo_app = code_app
        return cmdb_object

    def initialize_cmdb_object(self, request: ImportScanRequest) -> Cmdb:
        return Cmdb(
            product_type_name="ORPHAN_PRODUCT_TYPE",
            product_name=f"{request.code_app}_Product",
            tag_product="ORPHAN",
            product_description="Orphan Product Description",
            codigo_app=str(request.code_app),
        )

    def mapping_cmdb(self, data: dict) -> dict:
        return {key: data.get(value, "") for key, value in self.__mapping_cmdb.items()}

    def get_nested_data(self, response, keys: list) -> dict:
        data = response.json()
        for key in keys:
            if isinstance(data, dict) and key in data:
                data = data[key]
            elif isinstance(data, list) and isinstance(key, int):
                key = key if key >=0 else len(data) + key
                if 0 <= key < len(data):
                    data = data[key]
                else:
                    raise KeyError(f"Index '{key}' out of range in the current context.")
            else:
                raise KeyError(f"Key '{key}' not found or invalid in the current context.")
        return data

    def prepare_headers(self, headers: dict) -> dict:
        return {key: (self.__token if value == 'tokenvalue' else value) for key, value in headers.items()}
        
    def replace_placeholders(self, data, replacements):
        data = str(data)
        data = data.replace("codappvalue", replacements)
        try:
            return ast.literal_eval(data)
        except (SyntaxError, ValueError) as e:
            raise ValueError(f"Error converting string to dictionary: {e}")

