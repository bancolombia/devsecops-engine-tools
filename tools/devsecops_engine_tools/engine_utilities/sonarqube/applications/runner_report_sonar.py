from devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.aws.secrets_manager import (
    SecretsManager
)
from devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.azure.azure_devops import (
    AzureDevops
)
from devsecops_engine_tools.engine_utilities.sonarqube.infrastructure.defect_dojo.report_sonar_defect_dojo import(
    DefectDojoAdapter
)
from devsecops_engine_tools.engine_utilities.sonarqube.infrastructure.sonar.report_sonar import(
    SonarAdapter
)
from devsecops_engine_tools.engine_utilities.sonarqube.infrastructure.entry_points.entry_point_report_sonar import (
    init_report_sonar
)
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()

def runner_report_sonar():
    try:
        vulnerability_management_gateway = DefectDojoAdapter()
        secrets_manager_gateway = SecretsManager()
        devops_platform_gateway = AzureDevops()
        sonar_gateway = SonarAdapter()

        init_report_sonar(
            vulnerability_management_gateway=vulnerability_management_gateway,
            secrets_manager_gateway=secrets_manager_gateway,
            devops_platform_gateway=devops_platform_gateway,
            sonar_gateway=sonar_gateway,
            args={},
        )

    except Exception as e:
        logger.error("Error report_sonar: {0} ".format(str(e)))
        print(
            devops_platform_gateway.message(
                "error", "Error report_sonar: {0} ".format(str(e))
            )
        )
        print(devops_platform_gateway.result_pipeline("failed"))


if __name__ == "__main__":
    runner_report_sonar()