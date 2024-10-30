from devsecops_engine_tools.engine_utilities.sonarqube.src.infrastructure.helpers.utils import (
    set_repository
)
from devsecops_engine_tools.engine_core.src.infrastructure.helpers.util import (
    define_env
)
from devsecops_engine_tools.engine_core.src.domain.model.gateway.vulnerability_management_gateway import (
    VulnerabilityManagementGateway
)
from devsecops_engine_tools.engine_core.src.domain.model.gateway.secrets_manager_gateway import (
    SecretsManagerGateway
)
from devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway import (
    DevopsPlatformGateway
)
from devsecops_engine_tools.engine_utilities.sonarqube.src.domain.model.gateways.sonar_gateway import (
    SonarGateway
)
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()

class ReportSonar:
    def __init__(
        self,
        vulnerability_management_gateway: VulnerabilityManagementGateway,
        secrets_manager_gateway: SecretsManagerGateway,
        devops_platform_gateway: DevopsPlatformGateway,
        sonar_gateway: SonarGateway
    ):
        self.vulnerability_management_gateway = vulnerability_management_gateway
        self.secrets_manager_gateway = secrets_manager_gateway
        self.devops_platform_gateway = devops_platform_gateway
        self.sonar_gateway = sonar_gateway

    def process(self, args):
        pipeline_name = self.devops_platform_gateway.get_variable("pipeline_name")
        branch = self.devops_platform_gateway.get_variable("branch_name")

        compact_remote_config_url = self.devops_platform_gateway.get_base_compact_remote_config_url(args["remote_config_repo"])
        source_code_management_uri = set_repository(
            pipeline_name,
            self.devops_platform_gateway.get_source_code_management_uri()
        )
        config_tool = self.devops_platform_gateway.get_remote_config(
            args["remote_config_repo"],
            "/engine_core/ConfigTool.json"
        )
        environment = {"dev": "Development",
                       "qa": "Staging",
                       "pdn": "Production"}.get(define_env(None, branch))
        
        if args["use_secrets_manager"] == "true": 
            secret = self.secrets_manager_gateway.get_secret(config_tool)
        else: 
            secret = args

        report_config_tool = self.devops_platform_gateway.get_remote_config(
            args["remote_config_repo"],
            "/report_sonar/ConfigTool.json"
        )
        get_components = report_config_tool["PIPELINE_COMPONENTS"].get(pipeline_name)
        if get_components:
            project_keys = [f"{pipeline_name}_{component}" for component in get_components]
            print(f"Multiple project keys detected: {project_keys}")
            logger.info(f"Multiple project keys detected: {project_keys}")
        else:
            project_keys = self.sonar_gateway.get_project_keys(pipeline_name)

        for project_key in project_keys:
            try:
                findings = self.vulnerability_management_gateway.get_all(
                    service=project_key,
                    dict_args=args,
                    secret_tool=self.secrets_manager_gateway,
                    config_tool=config_tool
                )[0]
                filtered_findings = self.sonar_gateway.filter_by_sonarqube_tag(findings)
                sonar_vulnerabilities = self.sonar_gateway.get_vulnerabilities(
                    args["sonar_url"],
                    secret["token_sonar"],
                    project_key
                )

                for finding in filtered_findings:
                    related_vulnerability = self.sonar_gateway.find_issue_by_id(
                        sonar_vulnerabilities, 
                        finding.unique_id_from_tool
                    )
                    transition = None
                    if related_vulnerability:
                        if finding.active and related_vulnerability["status"] == "RESOLVED":
                            transition = "reopen"
                        elif related_vulnerability["status"] != "RESOLVED":
                            if finding.false_p:
                                transition = "falsepositive"
                            elif finding.risk_accepted:
                                transition = "close"
                            elif finding.mitigated:
                                transition = "resolved"

                        if transition:
                            self.sonar_gateway.change_issue_transition(
                                args["sonar_url"],
                                secret["token_sonar"],
                                finding.unique_id_from_tool,
                                transition
                            )
            except Exception as e:
                print(f"It was not possible to synchronize Sonar and Vulnerability Manager: {e}")
                logger.warning(f"It was not possible to synchronize Sonar and Vulnerability Manager: {e}")

            self.vulnerability_management_gateway.send_report(
                compact_remote_config_url,
                source_code_management_uri,
                environment,
                secret,
                config_tool,
                self.devops_platform_gateway,
                project_key
            )
