from devsecops_engine_tools.engine_utilities.sonarqube.domain.usecases.report_sonar import (
    ReportSonar
)
from devsecops_engine_tools.engine_utilities.utils.printers import (
    Printers,
)

def init_report_sonar(vulnerability_management_gateway, vulnerability_send_report_gateway, secrets_manager_gateway, devops_platform_gateway, sonar_gateway, args):
    Printers.print_logo_tool("Report Sonar")

    return ReportSonar(
        vulnerability_management_gateway,
        vulnerability_send_report_gateway,
        secrets_manager_gateway, 
        devops_platform_gateway, 
        sonar_gateway
        ).process(args)