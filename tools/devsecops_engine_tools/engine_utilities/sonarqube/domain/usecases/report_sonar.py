from devsecops_engine_tools.engine_core.src.domain.model.gateway.secrets_manager_gateway import (
    SecretsManagerGateway,
)
from devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway import (
    DevopsPlatformGateway,
)
from devsecops_engine_tools.engine_utilities.sonarqube.domain.model.gateways.vulnerability_management_gateway import (
    VulnerabilityManagementGateway
)
from devsecops_engine_tools.engine_utilities.sonarqube.infrastructure.sonar.report_sonar import (
    SendReportSonar
)
from devsecops_engine_tools.engine_utilities.sonarqube.infrastructure.helpers.utils import (
    set_repository, 
    set_environment, 
    invalid_pipeline,
    invalid_branch
)

class ReportSonar:
    def __init__(
        self,
        vulnerability_management_gateway: VulnerabilityManagementGateway,
        secrets_manager_gateway: SecretsManagerGateway,
        devops_platform_gateway: DevopsPlatformGateway,
        sonar_gateway
    ):
        self.vulnerability_management_gateway = vulnerability_management_gateway
        self.secrets_manager_gateway = secrets_manager_gateway
        self.devops_platform_gateway = devops_platform_gateway
        self.sonar_gateway = sonar_gateway

    def process(self, args):
        pipeline_name = self.devops_platform_gateway.get_variable("pipeline_name")
        branch = self.devops_platform_gateway.get_variable("branch_name")

        if invalid_pipeline(pipeline_name) or invalid_branch(branch):
            print("Send report sonar skipped by DevSecOps Policy.")
            print(self.devops_platform_gateway.result_pipeline("succeeded"))
            return

        compact_remote_config_url = self.devops_platform_gateway.get_base_compact_remote_config_url(
            args["remote_config_repo"]
        )
        source_code_management_uri = set_repository(
            pipeline_name,
            self.devops_platform_gateway.get_variable("repository")
        )
        config_tool = self.devops_platform_gateway.get_remote_config(
            args["remote_config_repo"],
            "/engine_core/ConfigTool.json"
        )
        environment = set_environment(branch)
        
        if self.secrets_manager_gateway: secret = self.secrets_manager_gateway.get_secret(config_tool)
        else: secret = args

        project_keys = self.sonar_gateway.get_project_keys(pipeline_name)

        for project_key in project_keys:
            self.vulnerability_management_gateway.send_report(
                compact_remote_config_url,
                source_code_management_uri,
                environment,
                secret["token_defect_dojo"],
                secret["token_cmdb"],
                config_tool,
                self.devops_platform_gateway,
                project_key
            )
