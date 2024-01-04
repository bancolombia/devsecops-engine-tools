from devsecops_engine_tools.engine_sast.engine_iac.src.applications.runner_iac_scan import (
    runner_engine_iac,
)
from devsecops_engine_tools.engine_sast.engine_secret.src.applications.runner_secret_scan import (
    runner_secret_scan
)
from devsecops_engine_tools.engine_core.src.domain.model.gateway.vulnerability_management_gateway import (
    VulnerabilityManagementGateway,
)
from devsecops_engine_tools.engine_core.src.domain.model.gateway.secrets_manager_gateway import (
    SecretsManagerGateway,
)
from devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway import (
    DevopsPlatformGateway,
)
from devsecops_engine_tools.engine_core.src.domain.model.vulnerability_management import (
    VulnerabilityManagement,
)
from devsecops_engine_tools.engine_core.src.domain.model.customs_exceptions import (
    ExceptionVulnerabilityManagement,
    ExceptionFindingsRiskAcceptance,
)


MESSAGE_ENABLED = "not yet enabled"


class HandleScan:
    def __init__(
        self,
        vulnerability_management: VulnerabilityManagementGateway,
        secrets_manager_gateway: SecretsManagerGateway,
        devops_platform_gateway: DevopsPlatformGateway,
        dict_args: any,
    ):
        self.vulnerability_management = vulnerability_management
        self.secrets_manager_gateway = secrets_manager_gateway
        self.devops_platform_gateway = devops_platform_gateway
        self.dict_args = dict_args

    def process(self):
        secret_tool = None
        config_tool = self.devops_platform_gateway.get_remote_config(self.dict_args)
        if self.dict_args["use_secrets_manager"] == "true":
            secret_tool = self.secrets_manager_gateway.get_secret(config_tool)
        if "engine_iac" in self.dict_args["tool"]:
            findings_list, input_core = runner_engine_iac(
                self.dict_args,
                config_tool["ENGINE_IAC"],
                secret_tool
            )
            if self.dict_args["use_vulnerability_management"] == "true":
                try:
                    self.vulnerability_management.send_vulnerability_management(
                        VulnerabilityManagement(
                            config_tool["ENGINE_IAC"],
                            input_core,
                            self.dict_args,
                            secret_tool,
                            config_tool,
                            self.devops_platform_gateway.get_source_code_management_uri(),
                            self.devops_platform_gateway.get_variable("branch_name"),
                            self.devops_platform_gateway.get_base_compact_remote_config_url(
                                self.dict_args["remote_config_repo"]
                            ),
                            self.devops_platform_gateway.get_variable("access_token"),
                            self.devops_platform_gateway.get_variable("version"),
                            self.devops_platform_gateway.get_variable("build_id"),
                            self.devops_platform_gateway.get_variable("branch_tag"),
                            self.devops_platform_gateway.get_variable("commit_hash"),
                            self.devops_platform_gateway.get_variable("environment"),
                        )
                    )
                except ExceptionVulnerabilityManagement as ex1:
                    print(self.devops_platform_gateway.logging("warning", str(ex1)))
                try:
                    input_core.totalized_exclusions.extend(
                        self.vulnerability_management.get_findings_risk_acceptance(
                            input_core.scope_pipeline,
                            self.dict_args,
                            secret_tool,
                            config_tool,
                        )
                    )
                except ExceptionFindingsRiskAcceptance as ex2:
                    print(self.devops_platform_gateway.logging("warning", str(ex2)))

            return findings_list, input_core
        elif "engine_dast" in self.dict_args["tool"]:
            print(MESSAGE_ENABLED)
        elif "engine_secret" in self.dict_args["tool"]:
            vulnerabilities_list, input_core = runner_secret_scan(
                self.dict_args["remote_config_repo"],
                "SAST/Secret_Scan/configTools.json",
                "trufflehog"
            )
            return vulnerabilities_list, input_core
        elif "engine_dependencies" in self.dict_args["tool"]:
            print(MESSAGE_ENABLED)
