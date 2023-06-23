import re
from defect_dojo.infraestructure.driver_adapters.cmdb import CmdbRestConsumer
from defect_dojo.domain.request_objects.import_scan import ImportScanRequest
from helper.validation_error import ValidationError
from helper.logger_info import MyLogger

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
        m = re.search(r"((AUD|AP|CLD|USR|OPS|ASN|AW|NU|EUC|IS)\d+)_", engagement_name, re.IGNORECASE)
        if m is None:
            logger.error(f"Engagement name {engagement_name} not match")
            raise ValidationError("Engagement name not match")
        code_app = m.group(1)
        logger.debug(code_app)
        return code_app.lower()
