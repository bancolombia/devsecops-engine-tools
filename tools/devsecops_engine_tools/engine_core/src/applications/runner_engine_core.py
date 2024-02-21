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
from devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.runtime_local.runtime_local import (
    RuntimeLocal,
)
from devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.aws.s3_manager import (
    S3Manager,
)
from devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.printer_pretty_table.printer_pretty_table import (
    PrinterPrettyTable,
)
import sys
import argparse
from devsecops_engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_utilities import settings


logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()

def get_inputs_from_cli(args):
    parser = argparse.ArgumentParser()
    parser.add_argument("--platform_devops", choices=["azure", "local"], type=str, required=True, help="")
    parser.add_argument("--remote_config_repo", type=str, required=True, help="")
    parser.add_argument(
        "--tool",
        choices=[
            "engine_iac",
            "engine_dast",
            "engine_secret",
            "engine_dependencies",
            "engine_container",
        ],
        type=str,
        required=True,
        help="",
    )
    parser.add_argument("--folder_path", type=str, required=False, help="")
    parser.add_argument(
        "--environment", choices=["dev", "qa", "pdn"], type=str, required=True, help=""
    )
    parser.add_argument(
        "--platform", choices=["eks", "openshift"], type=str, required=False, help=""
    )
    parser.add_argument(
        "--use_secrets_manager",
        choices=["true", "false"],
        type=str,
        required=False,
        help="",
    )
    parser.add_argument(
        "--use_vulnerability_management",
        choices=["true", "false"],
        type=str,
        required=False,
        help="",
    )
    parser.add_argument("--token_cmdb", required=False, help="")
    parser.add_argument("--token_vulnerability_management", required=False, help="")
    parser.add_argument("--token_engine_container", required=False, help="")
    parser.add_argument("--token_engine_dependencies", required=False, help="")
    args = parser.parse_args()
    return {
        "platform_devops": args.platform_devops,
        "remote_config_repo": args.remote_config_repo,
        "tool": args.tool,
        "folder_path": args.folder_path,
        "environment": args.environment,
        "platform": args.platform,
        "use_secrets_manager": args.use_secrets_manager,
        "use_vulnerability_management": args.use_vulnerability_management,
        "token_cmdb": args.token_cmdb,
        "token_vulnerability_management": args.token_vulnerability_management,
        "token_engine_container": args.token_engine_container,
        "token_engine_dependencies": args.token_engine_dependencies,
    }

def application_core():
    try:
        # Get inputs from CLI
        args = get_inputs_from_cli(sys.argv[1:])

        # Define driven adapters for gateways
        vulnerability_management_gateway = DefectDojoPlatform()
        secrets_manager_gateway = SecretsManager()
        devops_platform_gateway = AzureDevops() if args["platform_devops"] == "azure" else RuntimeLocal()
        printer_table_gateway = PrinterPrettyTable()
        metrics_manager_gateway = S3Manager()
        
        init_engine_core(
            vulnerability_management_gateway,
            secrets_manager_gateway,
            devops_platform_gateway,
            printer_table_gateway,
            metrics_manager_gateway,
            args
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
