from devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.aws.secrets_manager import (
    SecretsManager
)
from devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.azure.azure_devops import (
    AzureDevops
)
from devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.defect_dojo.defect_dojo import (
    DefectDojoPlatform
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
import sys
import argparse
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()

def get_inputs_from_cli(args):
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-rcf",
        "--remote_config_repo",
        type=str,
        required=True,
        help="Name of Config Repo",
    )
    parser.add_argument(
        "--use_secrets_manager",
        choices=["true", "false"],
        type=str,
        required=True,
        help="Use Secrets Manager to get the tokens",
    )
    parser.add_argument(
        "--sonar_url",
        required=False,
        help="Url to access sonar API",
    )
    parser.add_argument(
        "--token_cmdb", 
        required=False, 
        help="Token to connect to the CMDB"
    )
    parser.add_argument(
        "--token_vulnerability_management",
        required=False,
        help="Token to connect to the Vulnerability Management",
    )
    parser.add_argument(
        "--token_sonar",
        required=False,
        help="Token to access sonar server",
    )

    args = parser.parse_args()
    return {
        "remote_config_repo": args.remote_config_repo,
        "use_secrets_manager": args.use_secrets_manager,
        "sonar_url": args.sonar_url,
        "token_cmdb": args.token_cmdb,
        "token_vulnerability_management": args.token_vulnerability_management,
        "token_sonar": args.token_sonar,
    }

def runner_report_sonar():
    try:
        vulnerability_management_gateway = DefectDojoPlatform()
        vulnerability_send_report_gateway = DefectDojoAdapter()
        secrets_manager_gateway = SecretsManager()
        devops_platform_gateway = AzureDevops()
        sonar_gateway = SonarAdapter()
        args = get_inputs_from_cli(sys.argv[1:])

        init_report_sonar(
            vulnerability_management_gateway=vulnerability_management_gateway,
            vulnerability_send_report_gateway=vulnerability_send_report_gateway,
            secrets_manager_gateway=secrets_manager_gateway,
            devops_platform_gateway=devops_platform_gateway,
            sonar_gateway=sonar_gateway,
            args=args,
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