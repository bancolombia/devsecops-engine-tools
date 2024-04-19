from devsecops_engine_tools.engine_risk.src.domain.usecases.handle_remote_config import (
    HandleRemoteConfig,
)

from devsecops_engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()

def init_engine_risk(
        tool_remote, dict_args, findings 
):
    remote_config = tool_remote.get_remote_config(
        dict_args["remote_config_repo"], "Risk/configTools.json"
    )
    if len(findings):
        handle_remote_config = HandleRemoteConfig(
            remote_config, findings
        )
        findings = handle_remote_config.filter_by_tag()
        
    else:
        logger.info("No Findings found in Vultracker")
    return findings