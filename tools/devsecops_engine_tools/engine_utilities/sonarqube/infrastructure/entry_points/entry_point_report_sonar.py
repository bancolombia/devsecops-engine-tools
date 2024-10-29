from devsecops_engine_tools.engine_utilities.sonarqube.domain.usecases.report_sonar import (
    ReportSonar
)
from devsecops_engine_tools.engine_utilities.utils.printers import (
    Printers,
)
from devsecops_engine_tools.engine_core.src.domain.usecases.metrics_manager import (
    MetricsManager,
)
from devsecops_engine_tools.engine_core.src.domain.model.input_core import (
    InputCore
)

def init_report_sonar(vulnerability_management_gateway, secrets_manager_gateway, devops_platform_gateway, sonar_gateway, metrics_manager_gateway, args):
    Printers.print_logo_tool("Report Sonar")

    ReportSonar(
        vulnerability_management_gateway,
        secrets_manager_gateway, 
        devops_platform_gateway, 
        sonar_gateway
    ).process(args)

    config_tool = devops_platform_gateway.get_remote_config(
        args["remote_config_repo"], "/engine_core/ConfigTool.json"
    )

    input_core = InputCore(
        [],
        {},
        "",
        "",
        devops_platform_gateway.get_variable("pipeline_name"),
        devops_platform_gateway.get_variable("stage").capitalize(),
    )
    
    if args["send_metrics"] == "true":
        MetricsManager(devops_platform_gateway, metrics_manager_gateway).process(
            config_tool, input_core, {"tool": "report_sonar"}, ""
        )