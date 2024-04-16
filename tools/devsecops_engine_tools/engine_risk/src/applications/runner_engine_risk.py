from devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.defect_dojo.defect_dojo import (
    DefectDojoPlatform,
)
from devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.azure.azure_devops import (
    AzureDevops,
)
from devsecops_engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_utilities import settings


logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


def runner_engine_risk():
    try:
        vulnerability_management_gateway = DefectDojoPlatform()
        devops_platform_gateway = AzureDevops()
    except Exception as e:
        logger.error("Error in engine risk: {0} ".format(str(e)))
        print(
            devops_platform_gateway.message(
                "error", "Error in engine risk: {0} ".format(str(e))
            )
        )
        print(devops_platform_gateway.result_pipeline("failed"))