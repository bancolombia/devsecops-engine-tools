from devsecops_engine_tools.engine_integrations.src.domain.usecases.handle_integrations import (
    Integrations
)
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings
from devsecops_engine_tools.engine_utilities.utils.printers import (
    Printers,
)

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


def init_engine_integrations(
    vulnerability_management_gateway,
    secrets_manager_gateway,
    devops_platform_gateway,
    remote_config_source_gateway,
    metrics_manager_gateway,
    args,
):
    config_tool = remote_config_source_gateway.get_remote_config(
        args["remote_config_repo"], "/engine_core/ConfigTool.json", args["remote_config_branch"]
    )

    Printers.print_logo_tool(config_tool["BANNER"])

    return Integrations(
        vulnerability_management_gateway=vulnerability_management_gateway,
        secrets_manager_gateway=secrets_manager_gateway,
        devops_platform_gateway=devops_platform_gateway,
        remote_config_source_gateway=remote_config_source_gateway,
        metrics_manager_gateway=metrics_manager_gateway,
    ).process(args)
