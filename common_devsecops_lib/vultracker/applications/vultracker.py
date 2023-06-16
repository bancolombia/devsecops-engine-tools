from marshmallow import ValidationError
from devsecops_lib.helper.logger_info import MyLogger
from devsecops_lib.vultracker.infraestructure.driver_adapters.\
    import_scan import ImportScanRestConsumer
from devsecops_lib.vultracker.infraestructure.driver_adapters.\
    product_type import ProductTypeRestConsumer
from devsecops_lib.vultracker.infraestructure.driver_adapters.\
    product import ProductRestConsumer
from devsecops_lib.vultracker.infraestructure.driver_adapters.\
    scan_configurations import ScanConfigrationRestConsumer
from devsecops_lib.vultracker.domain.request_objects.import_scan\
    import ImportScanRequest
from devsecops_lib.vultracker.domain.user_case.import_scan import ImportScanUserCase
logger = MyLogger.__call__().get_logger()



class Vultracker:

    @staticmethod
    def send_import_scan(request: ImportScanRequest):
        try:
            rest_import_scan = ImportScanRestConsumer(request)
            rest_product_type = ProductTypeRestConsumer(request)
            rest_product = ProductRestConsumer(request)
            rest_scan_configuration = ScanConfigrationRestConsumer(request)
            uc = ImportScanUserCase(rest_import_scan,
                                    rest_product_type,
                                    rest_product,
                                    rest_scan_configuration)
            response = uc.execute(request)
            return response
        except ValidationError as error:
            logger.error(error.messages)
