# Description: This file is used to report the vulnerabilities to sonarqube vultracker.
from devsecops_engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_utilities import settings
from devsecops_engine_utilities.sonarqube.infraestructure.entry_point.entry_point_report_defect_dojo import(
    init_report_defect_dojo
)
from devsecops_engine_utilities.sonarqube.infraestructure.driven_adapter.aws.secrets_manager import(
    SecretsManager
)
from devsecops_engine_utilities.sonarqube.infraestructure.driven_adapter.azure.azure_devops import(
    AzureDevops
)
from devsecops_engine_utilities.sonarqube.infraestructure.driven_adapter.defect_dojo import(
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