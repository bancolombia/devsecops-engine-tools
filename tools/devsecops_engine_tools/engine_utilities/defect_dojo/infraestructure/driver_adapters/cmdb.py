import json
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
        data = json.dumps({"codapp": request.code_app})
        headers = {"tokenkey": self.__token, "Content-Type": "application/json"}
        logger.info("Search info of name product")
        cmdb_object = Cmdb(
                    product_type_name="ORPHAN_PRODUCT_TYPE",
                    product_name=f"{request.code_app}_Product",
                    tag_product="ORPHAN",
                    product_description="Orphan Product Description",
                    codigo_app=str(request.code_app),
                )
        try:
            response = self.__session.post(self.__host, headers=headers, data=data, verify=VERIFY_CERTIFICATE)
            if response.status_code != 200:
                logger.warning(response)
                raise ApiError(f"Error querying cmdb: {response.reason}")

            if response.json() == []:
                e = f"Engagement: {request.code_app} not found"
                logger.warning(e)
                # Producto is Orphan
                return cmdb_object

            data = response.json()[-1]
            data_map = self.mapping_cmdb(data)
            logger.info(data_map)
            cmdb_object = Cmdb.from_dict(data_map)
        except Exception as e:
            logger.warning(e)
            return cmdb_object
        return cmdb_object

    def mapping_cmdb(self, data):
        data_map = {}
        for key, value in self.__mapping_cmdb.items():
            data_map[key] = data[value] if value in data else ""
        return data_map