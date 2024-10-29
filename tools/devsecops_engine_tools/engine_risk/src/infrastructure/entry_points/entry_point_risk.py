from devsecops_engine_tools.engine_risk.src.domain.usecases.handle_filters import (
    HandleFilters,
)
from devsecops_engine_tools.engine_risk.src.domain.usecases.break_build import (
    BreakBuild,
)
from devsecops_engine_tools.engine_risk.src.domain.usecases.add_data import (
    AddData,
)
from devsecops_engine_tools.engine_risk.src.domain.usecases.get_exclusions import (
    GetExclusions,
)


import re

from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


def init_engine_risk(
    add_epss_gateway,
    devops_platform_gateway,
    print_table_gateway,
    dict_args,
    findings,
    services,
    vm_exclusions,
):
    remote_config = devops_platform_gateway.get_remote_config(
        dict_args["remote_config_repo"], "engine_risk/ConfigTool.json"
    )
    risk_exclusions = devops_platform_gateway.get_remote_config(
        dict_args["remote_config_repo"], "engine_risk/Exclusions.json"
    )

    return process_findings(
        findings,
        vm_exclusions,
        dict_args,
        services,
        risk_exclusions,
        remote_config,
        add_epss_gateway,
        devops_platform_gateway,
        print_table_gateway,
    )


def process_findings(
    findings,
    vm_exclusions,
    dict_args,
    services,
    risk_exclusions,
    remote_config,
    add_epss_gateway,
    devops_platform_gateway,
    print_table_gateway,
):
    if not findings:
        print("No findings found in Vulnerability Management Platform")
        logger.info("No findings found in Vulnerability Management Platform")
        return

    handle_filters = HandleFilters()

    return process_active_findings(
        handle_filters.filter(findings),
        findings,
        vm_exclusions,
        devops_platform_gateway,
        dict_args,
        remote_config,
        risk_exclusions,
        services,
        add_epss_gateway,
        print_table_gateway,
    )


def process_active_findings(
    active_findings,
    total_findings,
    vm_exclusions,
    devops_platform_gateway,
    dict_args,
    remote_config,
    risk_exclusions,
    services,
    add_epss_gateway,
    print_table_gateway,
):
    data_added = AddData(add_epss_gateway, active_findings).process()
    get_exclusions = GetExclusions(
        devops_platform_gateway,
        dict_args,
        data_added,
        remote_config,
        risk_exclusions,
        services,
    )
    exclusions = get_exclusions.process()
    break_build = BreakBuild(
        devops_platform_gateway,
        print_table_gateway,
        remote_config,
        exclusions,
        vm_exclusions,
        data_added,
        total_findings,
    )

    return break_build.process()
