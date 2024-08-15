from devsecops_engine_tools.engine_risk.src.domain.usecases.handle_filters import (
    HandleFilters,
)
from devsecops_engine_tools.engine_risk.src.domain.usecases.break_build import (
    BreakBuild,
)
from devsecops_engine_tools.engine_risk.src.domain.usecases.add_data import (
    AddData,
)

import re

from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


def init_engine_risk(devops_platform_gateway, print_table_gateway, dict_args, findings):
    remote_config = devops_platform_gateway.get_remote_config(
        dict_args["remote_config_repo"], "engine_risk/ConfigTool.json"
    )
    exclusions = devops_platform_gateway.get_remote_config(
        dict_args["remote_config_repo"], "engine_risk/Exclusions.json"
    )
    pipeline_name = devops_platform_gateway.get_variable("pipeline_name")
    if should_skip_analysis(remote_config, pipeline_name, exclusions):
        print("Tool skipped by DevSecOps Policy.")
        logger.info("Tool skipped by DevSecOps Policy.")
    else:
        process_findings(
            findings, remote_config, devops_platform_gateway, print_table_gateway
        )


def should_skip_analysis(remote_config, pipeline_name, exclusions):
    ignore_pattern = remote_config["IGNORE_ANALYSIS_PATTERN"]
    return re.match(ignore_pattern, pipeline_name, re.IGNORECASE) or (
        pipeline_name in exclusions and exclusions[pipeline_name].get("SKIP_TOOL", 0)
    )


def process_findings(
    findings, remote_config, devops_platform_gateway, print_table_gateway
):
    if not findings:
        print("No findings found in Vulnerability Management Platform")
        logger.info("No findings found in Vulnerability Management Platform")
        return

    handle_filters = HandleFilters()
    active_findings = handle_filters.filter(findings)
    if not active_findings:
        print("No active findings found in Vulnerability Management Platform")
        logger.info("No active findings found in Vulnerability Management Platform")
        return

    data_added = AddData(active_findings).add_data()
    BreakBuild(devops_platform_gateway, print_table_gateway, remote_config).process(
        data_added
    )
