from devsecops_engine_tools.engine_utilities.sonarqube.src.infrastructure.helpers.utils import (
    set_repository
)
from devsecops_engine_tools.engine_core.src.infrastructure.helpers.util import (
    define_env
)
from devsecops_engine_tools.engine_core.src.domain.model.gateway.vulnerability_management_gateway import (
    VulnerabilityManagementGateway
)
from devsecops_engine_tools.engine_core.src.domain.model.vulnerability_management import (
    VulnerabilityManagement
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
from devsecops_engine_tools.engine_core.src.domain.model.input_core import (
    InputCore
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
        branch = self.devops_platform_gateway.get_variable("branch_tag").replace("refs/heads/", "")
        input_core = InputCore(
            [],
            {},
            "",
            "",
            "",
            "",
            self.devops_platform_gateway.get_variable("stage").capitalize(),
        )

        compact_remote_config_url = self.devops_platform_gateway.get_base_compact_remote_config_url(args["remote_config_repo"])
        source_code_management_uri = set_repository(
            pipeline_name,
            self.devops_platform_gateway.get_source_code_management_uri()
        )
        config_tool = self.devops_platform_gateway.get_remote_config(
            args["remote_config_repo"],
            "/engine_core/ConfigTool.json",
            args["remote_config_branch"]
        )
        environment = define_env(None, branch)
        
        if args["use_secrets_manager"] == "true": 
            secret = self.secrets_manager_gateway.get_secret(config_tool)
            secret_tool = secret.copy()
            secret["token_sonar"] = (
                secret[f"token_{args['sonar_instance'].lower()}"]
                if args["sonar_instance"] is not None
                and f"token_{args['sonar_instance'].lower()}" in secret
                else secret["token_sonar"]
            )
        else: 
            secret = args
            secret_tool = None

        report_config_tool = self.devops_platform_gateway.get_remote_config(
            args["remote_config_repo"],
            "/report_sonar/ConfigTool.json",
            args["remote_config_branch"]
        )

        get_components = report_config_tool["PIPELINE_COMPONENTS"].get(pipeline_name)
        if get_components:
            project_keys = [f"{pipeline_name}_{component}" for component in get_components]
            print(f"Multiple project keys detected: {project_keys}")
            logger.info(f"Multiple project keys detected: {project_keys}")
        else:
            project_keys = self.sonar_gateway.get_project_keys(pipeline_name)

        args["module"] = "sonarqube"
        vulnerability_manager = VulnerabilityManagement(
            scan_type = "SONARQUBE",
            input_core = input_core,
            dict_args = args,
            secret_tool = secret_tool,
            config_tool = config_tool,
            source_code_management_uri = source_code_management_uri,
            base_compact_remote_config_url = compact_remote_config_url,
            sonar_instance = args["sonar_instance"],
            repository_provider = self.devops_platform_gateway.get_variable("repository_provider"),
            access_token = self.devops_platform_gateway.get_variable("access_token"),
            version = self.devops_platform_gateway.get_variable("build_execution_id"),
            build_id = self.devops_platform_gateway.get_variable("build_id"),
            branch_tag = branch,
            commit_hash = self.devops_platform_gateway.get_variable("commit_hash"),
            environment = environment,
            vm_product_type_name = self.devops_platform_gateway.get_variable("vm_product_type_name"),
            vm_product_name = self.devops_platform_gateway.get_variable("vm_product_name"),
            vm_product_description = self.devops_platform_gateway.get_variable("vm_product_description"),
        )

        for project_key in project_keys:
            try:
                findings = self.vulnerability_management_gateway.get_all(
                    service=project_key,
                    dict_args=args,
                    secret_tool=secret_tool,
                    config_tool=config_tool
                )[0]
                filtered_findings = self.sonar_gateway.filter_by_sonarqube_tag(findings)

                sonar_vulns_params = {
                    "componentKeys": project_key,
                    "types": "VULNERABILITY",
                    "ps": 500,
                    "p": 1,
                    "s": "CREATION_DATE",
                    "asc": "false"
                }
                sonar_hotspots_params = {
                    "projectKey": project_key,
                    "ps": 100,
                    "p": 1,
                }

                if report_config_tool["USE_BRANCH_PARAMETER"] and pipeline_name not in report_config_tool["USE_PULL_REQUEST_PARAMETER"]:
                    sonar_vulns_params["branch"] = branch
                    sonar_hotspots_params["branch"] = branch
                else:
                    try:
                        pull_request_id = int(self.devops_platform_gateway.get_variable("pull_request_id"))
                        sonar_vulns_params["pullRequest"] = pull_request_id
                        sonar_hotspots_params["pullRequest"] = pull_request_id
                    except Exception as e: pass

                sonar_vulnerabilities = self.sonar_gateway.get_findings(
                    args["sonar_url"],
                    secret["token_sonar"],
                    "/api/issues/search",
                    sonar_vulns_params,
                    "issues",
                    report_config_tool["MAX_RETRIES_QUERY_SONAR"]
                )
                sonar_hotspots = self.sonar_gateway.get_findings(
                    args["sonar_url"],
                    secret["token_sonar"],
                    "/api/hotspots/search",
                    sonar_hotspots_params,
                    "hotspots",
                    report_config_tool["MAX_RETRIES_QUERY_SONAR"]
                )

                sonar_findings = sonar_vulnerabilities + sonar_hotspots

                for finding in filtered_findings:
                    related_sonar_finding = self.sonar_gateway.search_finding_by_id(
                        sonar_findings, 
                        finding.unique_id_from_tool
                    )
                    status = None
                    if related_sonar_finding:
                        if related_sonar_finding.get("type") == "VULNERABILITY":
                            if finding.active and related_sonar_finding["status"] == "RESOLVED": status = "reopen"
                            elif related_sonar_finding["status"] != "RESOLVED":
                                if finding.false_p: status = "falsepositive"
                                elif finding.risk_accepted or finding.out_of_scope: status = "wontfix"
                            if status:
                                self.sonar_gateway.change_finding_status(
                                    args["sonar_url"],
                                    secret["token_sonar"],
                                    "/api/issues/do_transition",
                                    {
                                        "issue": related_sonar_finding["key"],
                                        "transition": status
                                    },
                                    "issue",
                                    report_config_tool["MAX_RETRIES_QUERY_SONAR"]
                                )
                        else:
                            resolution = None
                            if finding.active and related_sonar_finding["status"] == "REVIEWED": status = "TO_REVIEW"
                            elif related_sonar_finding["status"] == "TO_REVIEW":
                                if finding.false_p: resolution = "SAFE"
                                elif finding.risk_accepted or finding.out_of_scope: resolution = "ACKNOWLEDGED"
                                if resolution: status = "REVIEWED"
                            if status:
                                data = {
                                    "hotspot": related_sonar_finding["key"],
                                    "status": status,
                                    "resolution": resolution
                                }
                                if not resolution: data.pop("resolution")
                                self.sonar_gateway.change_finding_status(
                                    args["sonar_url"],
                                    secret["token_sonar"],
                                    "/api/hotspots/change_status",
                                    data,
                                    "hotspot",
                                    report_config_tool["MAX_RETRIES_QUERY_SONAR"]
                                )

            except Exception as e:
                logger.warning(f"It was not possible to synchronize Sonar and Vulnerability Manager: {e}")

            input_core.scope_pipeline = project_key
            input_core.scope_service = project_key

            self.vulnerability_management_gateway.send_vulnerability_management(
                vulnerability_management=vulnerability_manager
            )

        input_core.scope_pipeline = pipeline_name
        input_core.scope_service = pipeline_name
        return input_core