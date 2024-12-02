from devsecops_engine_tools.engine_utilities.utils.api_error import ApiError
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.import_scan import (
    ImportScanRestConsumer,
)
from devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.product_type import (
    ProductTypeRestConsumer,
)
from devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.product import (
    ProductRestConsumer,
)
from devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.scan_configurations import (
    ScanConfigrationRestConsumer,
)
from devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.engagement import (
    EngagementRestConsumer,
)
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.request_objects.import_scan import (
    ImportScanRequest,
)
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.user_case.import_scan import (
    ImportScanUserCase,
)
from devsecops_engine_tools.engine_utilities.utils.session_manager import SessionManager
from devsecops_engine_tools.engine_utilities.settings import SETTING_LOGGER

logger = MyLogger.__call__(**SETTING_LOGGER).get_logger()


class DefectDojo:
    @staticmethod
    def send_import_scan(request: ImportScanRequest):
        try:
            if not isinstance(request, ImportScanRequest):
                return request
            rest_import_scan = ImportScanRestConsumer(request, session=SessionManager())
            rest_product_type = ProductTypeRestConsumer(
                request, session=SessionManager()
            )
            rest_product = ProductRestConsumer(
                SessionManager(
                    request.token_defect_dojo,
                    request.host_defect_dojo,
                )
            )
            rest_engagement = EngagementRestConsumer(request, session=SessionManager())

            rest_scan_configuration = ScanConfigrationRestConsumer(
                request, session=SessionManager()
            )
            uc = ImportScanUserCase(
                rest_import_scan,
                rest_product_type,
                rest_product,
                rest_scan_configuration,
                rest_engagement=rest_engagement,
            )
            return uc.execute(request)
        except ApiError as e:
            logger.error(f"Error during import scan: {e}")
            raise e
