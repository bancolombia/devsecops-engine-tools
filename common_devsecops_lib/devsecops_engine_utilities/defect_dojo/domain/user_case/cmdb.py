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
    def __init__(self, rest_consumer_cmdb: CmdbRestConsumer) -> None:
        self.__rc_cmdb = rest_consumer_cmdb

    def execute(self, request: ImportScanRequest) -> ImportScanRequest:
        # self.get_cmdb_mapping()
        request.code_app = self.get_code_app(request.engagement_name)
        product_data = self.__rc_cmdb.get_product_info(request)
        request.product_type_name = product_type_name_map.get(
            product_data.product_type_name, product_data.product_type_name
        )
        request.product_name = product_data.product_name
        request.tags = product_data.tag_product
        request.product_description = product_data.product_description
        logger.info(f"product_type_name: {request.product_type_name}")
        logger.info(f"product_name: {request.product_name}")
        logger.info(f"tags product: {request.tags}")
        logger.info(f"product description: {request.product_description}")
        logger.info(f"code app:  {request.code_app}")
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

    def get_cmdb_mapping(self):
        azure_devops_api = AzureDevopsApi(
            personal_access_token=self.__settings.personal_access_token,
            system_team_project_id=self.__settings.system_team_project_id,
            organization_url=self.__settings.organization_url)

        azure_devops_api.get_remote_json_config(
            remote_config_repo=self.__settings.remote_config_repo,
            remote_config_path=self.__settings.remote_config_path)

