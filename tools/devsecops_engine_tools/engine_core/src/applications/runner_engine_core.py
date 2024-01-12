from devsecops_engine_tools.engine_core.src.infrastructure.entry_points.entry_point_core import (
    init_engine_core,
)
from devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.defect_dojo.defect_dojo import (
    DefectDojoPlatform,
)
from devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.aws.secrets_manager import (
    SecretsManager,
)
from devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.azure.azure_devops import (
    AzureDevops,
)
from devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.aws.s3_manager import (
    S3Manager,
)
from devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.printer_pretty_table.printer_pretty_table import (
    PrinterPrettyTable,
)
from devsecops_engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_utilities import settings


logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


def application_core():
    try:
        # Define driven adapters for gateways
        vulnerability_management_gateway = DefectDojoPlatform()
        secrets_manager_gateway = SecretsManager()
        devops_platform_gateway = AzureDevops()
        printer_table_gateway = PrinterPrettyTable()
        metrics_manager_gateway = S3Manager()

        init_engine_core(
            vulnerability_management_gateway,
            secrets_manager_gateway,
            devops_platform_gateway,
            printer_table_gateway,
            metrics_manager_gateway,
        )
    except Exception as e:
        logger.error("Error SCAN: {0} ".format(str(e)))
        print(
            devops_platform_gateway.message(
                "error", "Error SCAN: {0} ".format(str(e))
            )
        )
        print(devops_platform_gateway.result_pipeline("failed"))


if __name__ == "__main__":
    application_core()
