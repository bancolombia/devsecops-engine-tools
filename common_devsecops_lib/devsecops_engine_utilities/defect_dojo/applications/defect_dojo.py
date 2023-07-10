from marshmallow import ValidationError
from devsecops_engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_utilities.defect_dojo.infraestructure.driver_adapters.import_scan import ImportScanRestConsumer
from devsecops_engine_utilities.defect_dojo.infraestructure.driver_adapters.product_type import ProductTypeRestConsumer
from devsecops_engine_utilities.defect_dojo.infraestructure.driver_adapters.product import ProductRestConsumer
from devsecops_engine_utilities.defect_dojo.infraestructure.driver_adapters.scan_configurations import (
    ScanConfigrationRestConsumer,
)
from devsecops_engine_utilities.defect_dojo.domain.request_objects.import_scan import ImportScanRequest
from devsecops_engine_utilities.defect_dojo.domain.user_case.import_scan import ImportScanUserCase

logger = MyLogger.__call__().get_logger()


class DefectDojo:
    @staticmethod
    def send_import_scan(request: ImportScanRequest):
        try:
            rest_import_scan = ImportScanRestConsumer(request)
            rest_product_type = ProductTypeRestConsumer(request)
            rest_product = ProductRestConsumer(request)
            rest_scan_configuration = ScanConfigrationRestConsumer(request)
            uc = ImportScanUserCase(rest_import_scan, rest_product_type, rest_product, rest_scan_configuration)
            response = uc.execute(request)
            return response
        except ValidationError as error:
            logger.error(error.messages)
