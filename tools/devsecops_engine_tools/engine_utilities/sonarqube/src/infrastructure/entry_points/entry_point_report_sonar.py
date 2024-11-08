from devsecops_engine_tools.engine_utilities.sonarqube.src.domain.usecases.report_sonar import (
    ReportSonar
)
from devsecops_engine_tools.engine_utilities.utils.printers import (
    Printers,
)
from devsecops_engine_tools.engine_core.src.domain.usecases.metrics_manager import (
    MetricsManager,
)
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()

def init_report_sonar(vulnerability_management_gateway, secrets_manager_gateway, devops_platform_gateway, sonar_gateway, metrics_manager_gateway, args):
    config_tool = devops_platform_gateway.get_remote_config(
        args["remote_config_repo"], "/engine_core/ConfigTool.json"
    )
    Printers.print_logo_tool(config_tool["BANNER"])

    if config_tool["REPORT_SONAR"]["ENABLED"] == "true":
        input_core = ReportSonar(
            vulnerability_management_gateway,
            secrets_manager_gateway, 
            devops_platform_gateway, 
            sonar_gateway
        ).process(args)
        
        if args["send_metrics"] == "true":
            MetricsManager(devops_platform_gateway, metrics_manager_gateway).process(
                config_tool, input_core, {"tool": "report_sonar"}, ""
            )
    else:
        print(
            devops_platform_gateway.message(
                "warning", "DevSecOps Engine Tool - {0} in maintenance...".format("report_sonar")),
        )