from devsecops_engine_tools.engine_utilities.sonarqube.infrastructure.helpers.utils import (
    set_repository, 
    set_environment, 
    invalid_pipeline,
    invalid_branch
)

class ReportSonar:
    def __init__(
        self,
        vulnerability_management_gateway,
        vulnerability_send_report_gateway,
        secrets_manager_gateway,
        devops_platform_gateway,
        sonar_gateway
    ):
        self.vulnerability_management_gateway = vulnerability_management_gateway
        self.vulnerability_send_report_gateway = vulnerability_send_report_gateway
        self.secrets_manager_gateway = secrets_manager_gateway
        self.devops_platform_gateway = devops_platform_gateway
        self.sonar_gateway = sonar_gateway

    def process(self, args):
        pipeline_name = self.devops_platform_gateway.get_variable("pipeline_name")
        branch = self.devops_platform_gateway.get_variable("branch_name")

        if invalid_pipeline(pipeline_name):# or invalid_branch(branch):
            print("Report sonar sending was skipped by DevSecOps Policy.")
            print(self.devops_platform_gateway.result_pipeline("succeeded"))
            return

        compact_remote_config_url = self.devops_platform_gateway.get_base_compact_remote_config_url(
            args["remote_config_repo"]
        )
        source_code_management_uri = self.devops_platform_gateway.get_source_code_management_uri()
        config_tool = self.devops_platform_gateway.get_remote_config(
            args["remote_config_repo"],
            "/engine_core/ConfigTool.json"
        )
        environment = set_environment(branch)
        if args["use_secrets_manager"] == "true": 
            secret = self.secrets_manager_gateway.get_secret(config_tool)
        else: 
            secret = args

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
                        elif finding.mitigated and related_vulnerability["status"] != "RESOLVED":
                            if finding.false_p:
                                transition = "falsepositive"
                            elif finding.mitigated:
                                transition = "resolved"
                            elif finding.risk_accepted:
                                transition = "closed"

                        if transition:
                            self.sonar_gateway.change_issue_transition(
                                args["sonar_url"],
                                secret["token_sonar"],
                                finding.unique_id_from_tool,
                                transition
                            )
            except:
                print("It was not possible to synchronize Sonar and Vulnerability Manager.")

            self.vulnerability_send_report_gateway.send_report(
                compact_remote_config_url,
                source_code_management_uri,
                environment,
                secret,
                config_tool,
                self.devops_platform_gateway,
                project_key
            )
