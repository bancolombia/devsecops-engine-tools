from devsecops_engine_tools.engine_risk.src.domain.usecases.handle_filters import (
    HandleFilters,
)
from devsecops_engine_tools.engine_risk.src.domain.usecases.break_build import (
    BreakBuild,
)

from devsecops_engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()

def init_engine_risk(
        devops_platform_gateway, print_table_gateway, dict_args, findings 
):
    remote_config = devops_platform_gateway.get_remote_config(
        dict_args["remote_config_repo"], "Risk/configTools.json"
    )
    findings_to_break = []
    if len(findings):
        handle_filters = HandleFilters(
            remote_config,
        )
        findings_to_break = handle_filters.filter_by_status(findings)
        findings_to_break = handle_filters.filter_by_tag(findings_to_break)

        BreakBuild(devops_platform_gateway, print_table_gateway).process(
            findings_to_break,
        )

    else:
        print("No Findings found in Vultracker")
        logger.info("No Findings found in Vultracker")

    return findings_to_break