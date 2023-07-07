import re
from devsecops_engine_utilities.defect_dojo.infraestructure.driver_adapters.cmdb import CmdbRestConsumer
from devsecops_engine_utilities.defect_dojo.domain.request_objects.import_scan import ImportScanRequest
from devsecops_engine_utilities.defect_dojo.infraestructure.repository.settings import SettingRepo
from devsecops_engine_utilities.utils.validation_error import ValidationError
from devsecops_engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_utilities.utils.azure_devops_api import AzureDevopsApi

logger = MyLogger.__call__().get_logger()

product_type_name_map = {
    "ADMINISTRATIVO Y FINANCIERO": "Apoyo Administrativo Y Financiero",
    "ARQUITECTURA DE TI": "CDE - ARQUITECTURA DE TI",
    "AUTENTICACION Y MONITOREO": "EVC - AUTENTICACION Y MONITOREO",
    "BIENESTAR FINANCI MIS ALIADOS": "EVC - BIENESTAR FINANCIERO",
    "CDE ARQUITECTURA": "CDE - ARQUITECTURA DE TI",
    "CDE DEVSECOPS, ING. SOFTWARE Y PRUEBAS": "CDE - INGENIERIA DE SOFTWARE DEVEXP",
}


class CmdbUserCase:
    def __init__(self, rest_consumer_cmdb: CmdbRestConsumer,
                 utils_azure: AzureDevopsApi) -> None:

        self.__rc_cmdb = rest_consumer_cmdb
        self.__utils_azure = utils_azure

    def execute(self, request: ImportScanRequest) -> ImportScanRequest:
        # Connection config map
        connection = self.__utils_azure.get_azure_connection()
        product_type_name_map = self.__utils_azure.get_remote_json_config(
            connection=connection,
            repository_id=request.repository_id,
            remote_config_path=request.remote_config_path)

        # regular exprecion
        request.code_app = self.get_code_app(request.engagement_name)

        # connect cmdb
        product_data = self.__rc_cmdb.get_product_info(request)
        request.product_type_name = product_type_name_map.get(
            product_data.product_type_name, product_data.product_type_name
        )
        request.product_name = product_data.product_name
        request.tags = product_data.tag_product
        request.product_description = product_data.product_description

        return request

    def get_code_app(self, engagement_name: str):
        m = re.search(r"((AUD|AP|CLD|USR|OPS|ASN|AW|NU|EUC|IS)\d+)_",
                      engagement_name, re.IGNORECASE)
        if m is None:
            logger.error(f"Engagement name {engagement_name} not match")
            raise ValidationError("Engagement name not match")
        code_app = m.group(1)
        logger.debug(code_app)
        return code_app.lower()


