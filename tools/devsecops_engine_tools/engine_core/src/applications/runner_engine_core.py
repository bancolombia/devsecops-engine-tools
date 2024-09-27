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
from devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.github.github_actions import (
    GithubActions,
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
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings
from devsecops_engine_tools.version import version


logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


def parse_separated_list(value, choices):
    values = value.split(",")
    # Validar cada elemento de la lista
    for val in values:
        if val not in choices:
            raise argparse.ArgumentTypeError(
                f"Invalid value: {val}. Valid values are: {', '.join(choices)}"
            )

    return values


def parse_choices(choices):
    def parse_with_choices(value):
        return parse_separated_list(value, choices)

    return parse_with_choices


def get_inputs_from_cli(args):
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-v", "--version", action="version", version="{version}".format(version=version)
    )
    parser.add_argument(
        "-pd",
        "--platform_devops",
        choices=["azure", "github", "local"],
        type=str,
        required=True,
        help="Platform where is executed",
    )
    parser.add_argument(
        "-rcf",
        "--remote_config_repo",
        type=str,
        required=True,
        help="Name or Folder Path of Config Repo",
    )
    parser.add_argument(
        "-t",
        "--tool",
        choices=[
            "engine_iac",
            "engine_dast",
            "engine_code",
            "engine_secret",
            "engine_dependencies",
            "engine_container",
            "engine_risk",
        ],
        type=str,
        required=True,
        help="Tool to execute",
    )
    parser.add_argument(
        "-fp",
        "--folder_path",
        type=str,
        required=False,
        help="Folder Path to scan, only apply engine_iac, engine_code and engine_dependencies tools",
    )
    parser.add_argument(
        "-p",
        "--platform",
        type=parse_choices({"all", "docker", "k8s", "cloudformation", "openapi"}),
        required=False,
        default="all",
        help="Platform to scan, only apply engine_iac tool",
    )
    parser.add_argument(
        "--use_secrets_manager",
        choices=["true", "false"],
        type=str,
        required=False,
        help="Use Secrets Manager to get the tokens",
    )
    parser.add_argument(
        "--use_vulnerability_management",
        choices=["true", "false"],
        type=str,
        required=False,
        help="Use Vulnerability Management to send the vulnerabilities to the platform",
    )
    parser.add_argument(
        "--send_metrics",
        choices=["true", "false"],
        type=str,
        required=False,
        help="Enable or Disable the send metrics to the driven adapter metrics",
    )
    parser.add_argument(
        "--token_cmdb", required=False, help="Token to connect to the CMDB"
    )
    parser.add_argument(
        "--token_vulnerability_management",
        required=False,
        help="Token to connect to the Vulnerability Management",
    )
    parser.add_argument(
        "--token_engine_container",
        required=False,
        help="Token to execute engine_container if is necessary",
    )
    parser.add_argument(
        "--token_engine_dependencies",
        required=False,
        help="Token to execute engine_dependencies if is necessary. If using xray as engine_dependencies tool, the token is the base64 of artifactory server config that can be obtain from jfrog cli with 'jf config export <ServerID>' command.",
    )
    parser.add_argument(
        "--token_external_checks",
        required=False,
        help="Token for downloading external checks from engine_iac if is necessary. Ej: github:token, ssh:privatekey:pass",
    )
    parser.add_argument(
        "--xray_mode",
        choices=["scan", "audit"],
        required=False,
        default="scan",
        help="Mode to execute xray, only apply engine_dependencies xray tool",
    )
    parser.add_argument(
        "--image_to_scan",
        required=False,
        help="Name of image to scan for engine_container",
    )
    args = parser.parse_args()
    return {
        "platform_devops": args.platform_devops,
        "remote_config_repo": args.remote_config_repo,
        "tool": args.tool,
        "folder_path": args.folder_path,
        "platform": args.platform,
        "use_secrets_manager": args.use_secrets_manager,
        "use_vulnerability_management": args.use_vulnerability_management,
        "send_metrics": args.send_metrics,
        "token_cmdb": args.token_cmdb,
        "token_vulnerability_management": args.token_vulnerability_management,
        "token_engine_container": args.token_engine_container,
        "token_engine_dependencies": args.token_engine_dependencies,
        "token_external_checks": args.token_external_checks,
        "xray_mode": args.xray_mode,
        "image_to_scan": args.image_to_scan
    }


def application_core():
    try:
        # Get inputs from CLI
        args = get_inputs_from_cli(sys.argv[1:])

        # Define driven adapters for gateways
        vulnerability_management_gateway = DefectDojoPlatform()
        secrets_manager_gateway = SecretsManager()
        devops_platform_gateway = {
            "azure": AzureDevops(),
            "github": GithubActions(),
            "local": RuntimeLocal(),
        }.get(args["platform_devops"])
        printer_table_gateway = PrinterPrettyTable()
        metrics_manager_gateway = S3Manager()

        init_engine_core(
            vulnerability_management_gateway,
            secrets_manager_gateway,
            devops_platform_gateway,
            printer_table_gateway,
            metrics_manager_gateway,
            args,
        )
    except Exception as e:
        logger.error("Error engine_core: {0} ".format(str(e)))
        print(
            devops_platform_gateway.message(
                "error", "Error engine_core: {0} ".format(str(e))
            )
        )
        print(devops_platform_gateway.result_pipeline("failed"))


if __name__ == "__main__":
    application_core()
