from devsecops_engine_tools.engine_core.src.domain.model.gateway.vulnerability_management_gateway import (
    VulnerabilityManagementGateway,
)
from devsecops_engine_tools.engine_core.src.domain.model.gateway.secrets_manager_gateway import (
    SecretsManagerGateway,
)
from devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway import (
    DevopsPlatformGateway,
)
from devsecops_engine_tools.engine_core.src.domain.model.gateway.printer_table_gateway import (
    PrinterTableGateway,
)
from devsecops_engine_tools.engine_risk.src.applications.runner_engine_risk import (
    runner_engine_risk,
)
from devsecops_engine_tools.engine_core.src.domain.model.customs_exceptions import (
    ExceptionGettingFindings,
)

from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


class HandleRisk:
    def __init__(
        self,
        vulnerability_management: VulnerabilityManagementGateway,
        secrets_manager_gateway: SecretsManagerGateway,
        devops_platform_gateway: DevopsPlatformGateway,
        print_table_gateway: PrinterTableGateway,
    ):
        self.vulnerability_management = vulnerability_management
        self.secrets_manager_gateway = secrets_manager_gateway
        self.devops_platform_gateway = devops_platform_gateway
        self.print_table_gateway = print_table_gateway

    def get_finding_list(self, dict_args, secret_tool, remote_config):
        try:
            findigs_list = self.vulnerability_management.get_all_findings(
                self.devops_platform_gateway.get_variable("pipeline_name"),
                dict_args,
                secret_tool,
                remote_config,
            )
            return findigs_list
        except ExceptionGettingFindings as e:
            logger.error("Error getting finding list in handle risk: {0}".format(str(e)))


    def process(self, dict_args: any, remote_config: any):
        secret_tool = None
        if dict_args["use_secrets_manager"] == "true":
            secret_tool = self.secrets_manager_gateway.get_secret(remote_config)

        findigs_list = self.get_finding_list(dict_args, secret_tool, remote_config)

        runner_engine_risk(
            dict_args,
            findigs_list,
            self.devops_platform_gateway,
            self.print_table_gateway
        )
