from devsecops_engine_tools.engine_core.src.domain.model.InputCore import InputCore
from devsecops_engine_tools.engine_sast.engine_iac.src.applications.runner_iac_scan import (
    runner_engine_iac,
)
from devsecops_engine_tools.engine_core.src.domain.model.gateway.gateway_deserealizator import (
    DeseralizatorGateway,
)
from devsecops_engine_tools.engine_core.src.domain.model.gateway.vulnerability_management_gateway import (
    VulnerabilityManagementGateway,
)
from devsecops_engine_tools.engine_core.src.domain.model.gateway.secrets_manager_gateway import (
    SecretsManagerGateway,
)


MESSAGE_ENABLED = "not yet enabled"


class HandleScan:
    def __init__(
        self,
        vulnerability_management: VulnerabilityManagementGateway,
        deseralizator_gateway: DeseralizatorGateway,
        secrets_manager_gateway: SecretsManagerGateway,
        dict_args: any,
    ):
        self.vulnerability_management = vulnerability_management
        self.deseralizator_gateway = deseralizator_gateway
        self.secrets_manager_gateway = secrets_manager_gateway
        self.dict_args = dict_args

    def process(self):
        if self.dict_args["use_secrets_manager"]:
            self.secret_tool = self.secrets_manager_gateway.get_secret(self.dict_args)
        if "engine_iac" in self.dict_args["tool"]:
            result_list_engine_iac = runner_engine_iac(
                self.dict_args["azure_remote_config_repo"],
                "SAST/IAC/configTools.json",
                "CHECKOV",
                self.dict_args["environment"],
            )
            if self.dict_args["send_to_defectdojo"]:
                self.vulnerability_management.send_vulnerability_management(
                    "Checkov Scan",
                    result_list_engine_iac.results_scan_list,
                    self.dict_args,
                    self.secret_tool
                )
            rules_scaned = result_list_engine_iac.rules_scaned
            totalized_exclusions = result_list_engine_iac.exclusions_all
            if result_list_engine_iac.exclusions_scope != None:
                totalized_exclusions.update(result_list_engine_iac.exclusions_scope)
            level_compliance_defined = result_list_engine_iac.level_compliance
            scope_pipeline = result_list_engine_iac.scope_pipeline
            vulnerabilities_list = self.deseralizator_gateway.get_list_vulnerability(
                result_list_engine_iac.results_scan_list
            )
            input_core = InputCore(
                totalized_exclusions=totalized_exclusions,
                level_compliance_defined=level_compliance_defined,
                rules_scaned=rules_scaned,
                scope_pipeline=scope_pipeline,
            )
            return vulnerabilities_list, input_core
        elif "engine_dast" in self.dict_args["tool"]:
            print(MESSAGE_ENABLED)
        elif "engine_secret" in self.dict_args["tool"]:
            print(MESSAGE_ENABLED)
        elif "engine_dependencies" in self.dict_args["tool"]:
            print(MESSAGE_ENABLED)
