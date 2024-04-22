import argparse
import sys
from devsecops_engine_tools.engine_core.src.domain.usecases.break_build import (
    BreakBuild,
)
from devsecops_engine_tools.engine_core.src.domain.usecases.handle_scan import (
    HandleScan,
)
from devsecops_engine_tools.engine_core.src.domain.usecases.handle_risk import (
    HandleRisk,
)
from devsecops_engine_tools.engine_core.src.domain.usecases.metrics_manager import (
    MetricsManager,
)
from devsecops_engine_utilities.utils.printers import (
    Printers,
)


def get_inputs_from_cli(args):
    parser = argparse.ArgumentParser()
    parser.add_argument("--remote_config_repo", type=str, required=True, help="")
    parser.add_argument(
        "--tool",
        choices=[
            "engine_iac",
            "engine_dast",
            "engine_secret",
            "engine_dependencies",
            "engine_container",
            "engine_risk",
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
    parser.add_argument(
        "--send_metrics",
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
        "remote_config_repo": args.remote_config_repo,
        "tool": args.tool,
        "folder_path": args.folder_path,
        "environment": args.environment,
        "platform": args.platform,
        "use_secrets_manager": args.use_secrets_manager,
        "use_vulnerability_management": args.use_vulnerability_management,
        "send_metrics": args.send_metrics,
        "token_cmdb": args.token_cmdb,
        "token_vulnerability_management": args.token_vulnerability_management,
        "token_engine_container": args.token_engine_container,
        "token_engine_dependencies": args.token_engine_dependencies,
    }


def init_engine_core(
    vulnerability_management_gateway: any,
    secrets_manager_gateway: any,
    devops_platform_gateway: any,
    print_table_gateway: any,
    metrics_manager_gateway: any,
):
    Printers.print_logo_tool()
    args = get_inputs_from_cli(sys.argv[1:])
    config_tool = devops_platform_gateway.get_remote_config(
        args["remote_config_repo"], "/resources/ConfigTool.json"
    )

    if (args["tool"] == "engine_risk") and (config_tool[args["tool"].upper()]["ENABLED"] == "true"):
        HandleRisk(
            vulnerability_management_gateway,
            secrets_manager_gateway,
            devops_platform_gateway,
        ).process(args, config_tool)

    elif config_tool[args["tool"].upper()]["ENABLED"] == "true":
        findings_list, input_core = HandleScan(
            vulnerability_management_gateway,
            secrets_manager_gateway,
            devops_platform_gateway,
        ).process(args, config_tool)

        scan_result = BreakBuild(devops_platform_gateway, print_table_gateway).process(
            findings_list,
            input_core,
        )
        if args["send_metrics"] == "true":
            MetricsManager(devops_platform_gateway, metrics_manager_gateway).process(
                config_tool, input_core, args, scan_result
            )
    else:
        print(
            devops_platform_gateway.message(
                "warning",
                "DevSecOps Engine Tool - {0} in maintenance...".format(args["tool"]),
            )
        )
