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
    add_epss_gateway, devops_platform_gateway, print_table_gateway, dict_args, parent_findings, findings
):
    remote_config = devops_platform_gateway.get_remote_config(
        dict_args["remote_config_repo"], "engine_risk/ConfigTool.json"
    )
    risk_exclusions = devops_platform_gateway.get_remote_config(
        dict_args["remote_config_repo"], "engine_risk/Exclusions.json"
    )
    pipeline_name = devops_platform_gateway.get_variable("pipeline_name")
    if should_skip_analysis(remote_config, pipeline_name, risk_exclusions):
        print("Tool skipped by DevSecOps Policy.")
        logger.info("Tool skipped by DevSecOps Policy.")
    else:
        process_findings(
            parent_findings,
            findings,
            dict_args,
            pipeline_name,
            risk_exclusions,
            remote_config,
            add_epss_gateway,
            devops_platform_gateway,
            print_table_gateway,
        )


def should_skip_analysis(remote_config, pipeline_name, exclusions):
    ignore_pattern = remote_config["IGNORE_ANALYSIS_PATTERN"]
    return re.match(ignore_pattern, pipeline_name, re.IGNORECASE) or (
        pipeline_name in exclusions and exclusions[pipeline_name].get("SKIP_TOOL", 0)
    )


def process_active_findings(
    active_findings,
    total_findings,
    devops_platform_gateway,
    dict_args,
    remote_config,
    risk_exclusions,
    pipeline_name,
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
        pipeline_name,
    )
    exclusions = get_exclusions.process()
    BreakBuild(
        devops_platform_gateway, print_table_gateway, remote_config, exclusions
    ).process(total_findings, data_added)


def process_findings(
    parent_findings,
    findings,
    dict_args,
    pipeline_name,
    risk_exclusions,
    remote_config,
    add_epss_gateway,
    devops_platform_gateway,
    print_table_gateway,
):
    if not findings and not parent_findings:
        print("No findings found in Vulnerability Management Platform")
        logger.info("No findings found in Vulnerability Management Platform")
        return

    handle_filters = HandleFilters()

    if parent_findings:
        parent_identifier = remote_config["PARENT_ANALYSIS"]["PARENT_IDENTIFIER"]
        parent_service = pipeline_name.split(parent_identifier)[0] + parent_identifier
        print(f"\nGenerating report for {parent_service}")
        logger.info(f"Generating report for {parent_service}")
        process_active_findings(
            handle_filters.filter(parent_findings),
            parent_findings,
            devops_platform_gateway,
            dict_args,
            remote_config,
            risk_exclusions,
            pipeline_name,
            add_epss_gateway,
            print_table_gateway,
        )

    if findings:
        print(f"\nGenerating report for {pipeline_name}")
        logger.info(f"Generating report for {pipeline_name}")
        process_active_findings(
            handle_filters.filter(findings),
            findings,
            devops_platform_gateway,
            dict_args,
            remote_config,
            risk_exclusions,
            pipeline_name,
            add_epss_gateway,
            print_table_gateway,
        )
