# Description: This file is used to report the vulnerabilities to sonarqube vultracker.
from engine_utilities.utils.logger_info import MyLogger
from engine_utilities import settings
from engine_utilities.sonarqube.infraestructure.entry_point.entry_point_report_defect_dojo import(
    init_report_defect_dojo
)
from engine_core.src.infrastructure.driven_adapters.aws.secrets_manager import(
    SecretsManager
)
from engine_core.src.infrastructure.driven_adapters.azure.azure_devops import(
    AzureDevops
)
from engine_utilities.sonarqube.infraestructure.driven_adapter.defect_dojo import(
    DefectDojoAdapter
)

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()

def task_core():
    init_report_defect_dojo(
        SecretsManager(),
        AzureDevops(),
        DefectDojoAdapter()
    )

if __name__ == "__main__":
    task_core()