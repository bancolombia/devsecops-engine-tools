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
from devsecops_engine_tools.engine_utilities.utils.printers import (
    Printers,
)

def init_engine_core(
    vulnerability_management_gateway: any,
    secrets_manager_gateway: any,
    devops_platform_gateway: any,
    remote_config_source_gateway: any,
    print_table_gateway: any,
    metrics_manager_gateway: any,
    sbom_tool_gateway: any,
    args: any
):
    config_tool = remote_config_source_gateway.get_remote_config(
        args["remote_config_repo"], "/engine_core/ConfigTool.json", args["remote_config_branch"]
    )
    Printers.print_logo_tool(config_tool["BANNER"])
    sbom_tool_gateway = sbom_tool_gateway.get(config_tool["SBOM_MANAGER"]["TOOL"].lower())

    if config_tool[args["module"].upper()]["ENABLED"]:
        if args["module"] == "engine_risk":
            results, input_core = HandleRisk(
                vulnerability_management_gateway,
                secrets_manager_gateway,
                devops_platform_gateway,
                remote_config_source_gateway,
                print_table_gateway,
            ).process(args, config_tool)

        else:
            if args.get("tool"):
                config_tool[args["module"].upper()]["TOOL"] = args.get("tool").upper()
                
            findings_list, input_core = HandleScan(
                vulnerability_management_gateway,
                secrets_manager_gateway,
                devops_platform_gateway,
                remote_config_source_gateway,
                sbom_tool_gateway
            ).process(args, config_tool)

            warning_release = config_tool["WARNING_RELEASE"]

            results = BreakBuild(devops_platform_gateway, print_table_gateway).process(
                findings_list,
                input_core,
                args,
                warning_release
            )
        if args["send_metrics"] == "true":
            MetricsManager(devops_platform_gateway, metrics_manager_gateway).process(
                config_tool, input_core, args, results
            )
    else:
        print(
            devops_platform_gateway.message(
                "warning",
                "DevSecOps Engine Tool - {0} in maintenance...".format(args["module"]),
            )
        )
