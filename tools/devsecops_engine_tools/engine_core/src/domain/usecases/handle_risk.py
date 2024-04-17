from devsecops_engine_tools.engine_core.src.domain.model.gateway.vulnerability_management_gateway import (
    VulnerabilityManagementGateway,
)
from devsecops_engine_tools.engine_core.src.domain.model.gateway.secrets_manager_gateway import (
    SecretsManagerGateway,
)
from devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway import (
    DevopsPlatformGateway,
)
from devsecops_engine_tools.engine_core.src.infrastructure.helpers.util import (
    get_scope_pipeline,
)
from devsecops_engine_tools.engine_risk.src.applications.runner_engine_risk import (
    runner_engine_risk,
)

from devsecops_engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


class HandleRisk:
    def __init__(
        self,
        vulnerability_management: VulnerabilityManagementGateway,
        secrets_manager_gateway: SecretsManagerGateway,
        devops_platform_gateway: DevopsPlatformGateway,
    ):
        self.vulnerability_management = vulnerability_management
        self.secrets_manager_gateway = secrets_manager_gateway
        self.devops_platform_gateway = devops_platform_gateway

    def process(self, dict_args: any, remote_config: any):
        secret_tool = None
        scope_pipeline = get_scope_pipeline(
            self.devops_platform_gateway.get_variable("release_name"),
            self.devops_platform_gateway.get_variable("pipeline_name")
        )
        if dict_args["use_secrets_manager"] == "true":
            secret_tool = self.secrets_manager_gateway.get_secret(remote_config)
        try:
            findigs_list = self.vulnerability_management.get_findings(
                scope_pipeline,
                dict_args,
                secret_tool,
                remote_config,
            )
            return runner_engine_risk(findigs_list, remote_config)
        except Exception as e:
            logger.error("Error in handle risk: {0} ".format(str(e)))
            print(
                self.devops_platform_gateway.message(
                    "error", "Error in handle risk: {0} ".format(str(e))
                )
            )
            print(self.devops_platform_gateway.result_pipeline("failed"))