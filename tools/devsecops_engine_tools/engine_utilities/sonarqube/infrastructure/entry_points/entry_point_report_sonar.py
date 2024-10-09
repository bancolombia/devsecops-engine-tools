from devsecops_engine_tools.engine_utilities.sonarqube.domain.usecases.report_sonar import (
    ReportSonar
)

def init_report_sonar(vulnerability_management_gateway, secrets_manager_gateway, devops_platform_gateway, sonar_gateway, args):
    return ReportSonar(
        vulnerability_management_gateway, 
        secrets_manager_gateway, 
        devops_platform_gateway, 
        sonar_gateway
        ).process(args)