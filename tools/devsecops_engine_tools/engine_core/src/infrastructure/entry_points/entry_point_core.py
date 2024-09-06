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
    print_table_gateway: any,
    metrics_manager_gateway: any,
    args: any
):
    config_tool = devops_platform_gateway.get_remote_config(
        args["remote_config_repo"], "/engine_core/ConfigTool.json"
    )
    Printers.print_logo_tool(config_tool["BANNER"])

    if config_tool[args["tool"].upper()]["ENABLED"] == "true":
        if args["tool"] == "engine_risk":
            results, input_core = HandleRisk(
                vulnerability_management_gateway,
                secrets_manager_gateway,
                devops_platform_gateway,
                print_table_gateway,
            ).process(args, config_tool)

        else:
            findings_list, input_core = HandleScan(
                vulnerability_management_gateway,
                secrets_manager_gateway,
                devops_platform_gateway,
            ).process(args, config_tool)

            results = BreakBuild(devops_platform_gateway, print_table_gateway).process(
                findings_list,
                input_core,
                args
            )
        if args["send_metrics"] == "true":
            MetricsManager(devops_platform_gateway, metrics_manager_gateway).process(
                config_tool, input_core, args, results
            )
    else:
        print(
            devops_platform_gateway.message(
                "warning",
                "DevSecOps Engine Tool - {0} in maintenance...".format(args["tool"]),
            )
        )
