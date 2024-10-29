from devsecops_engine_tools.engine_utilities.sonarqube.src.domain.usecases.report_sonar import (
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
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()

def init_report_sonar(vulnerability_management_gateway, secrets_manager_gateway, devops_platform_gateway, sonar_gateway, metrics_manager_gateway, args):
    Printers.print_logo_tool("Report Sonar")
    config_tool = devops_platform_gateway.get_remote_config(
        args["remote_config_repo"], "/engine_core/ConfigTool.json"
    )

    if config_tool["REPORT_SONAR"]["ENABLED"] != "true":
        print("Report sonar sending is temporarily disabled by DevSecOps Policy.")
        logger.info("Report sonar sending is temporarily disabled by DevSecOps Policy.")
        if args["send_metrics"] == "true":
            send_metrics(devops_platform_gateway, metrics_manager_gateway, config_tool)
        return

    ReportSonar(
        vulnerability_management_gateway,
        secrets_manager_gateway, 
        devops_platform_gateway, 
        sonar_gateway
    ).process(args)
    
    if args["send_metrics"] == "true":
        send_metrics(devops_platform_gateway, metrics_manager_gateway, config_tool)

def send_metrics(devops_platform_gateway, metrics_manager_gateway, config_tool):
    input_core = InputCore(
        [],
        {},
        "",
        "",
        devops_platform_gateway.get_variable("pipeline_name"),
        devops_platform_gateway.get_variable("stage").capitalize(),
    )

    MetricsManager(devops_platform_gateway, metrics_manager_gateway).process(
        config_tool, input_core, {"tool": "report_sonar"}, ""
    )