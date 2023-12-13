from devsecops_engine_tools.engine_sast.engine_iac.src.applications.runner_iac_scan import (
    runner_engine_iac,
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
        if self.dict_args["use_secrets_manager"] == "True":
            secret_tool = self.secrets_manager_gateway.get_secret(config_tool)
        if "engine_iac" in self.dict_args["tool"]:
            vulnerabilities_list, input_core = runner_engine_iac(
                self.dict_args["remote_config_repo"],
                "SAST/IAC/configTools.json",
                "CHECKOV",
                self.dict_args["environment"],
            )
            if self.dict_args["use_vulnerability_management"] == "True":
                self.vulnerability_management.send_vulnerability_management(
                    "Checkov Scan",
                    input_core,
                    self.dict_args,
                    secret_tool,
                    config_tool,
                )
                input_core.totalized_exclusions.extend(
                    self.vulnerability_management.get_findings_risk_acceptance(
                        input_core.scope_pipeline,
                        self.dict_args,
                        secret_tool,
                        config_tool,
                    )
                )

            return vulnerabilities_list, input_core
        elif "engine_dast" in self.dict_args["tool"]:
            print(MESSAGE_ENABLED)
        elif "engine_secret" in self.dict_args["tool"]:
            print(MESSAGE_ENABLED)
        elif "engine_dependencies" in self.dict_args["tool"]:
            print(MESSAGE_ENABLED)
