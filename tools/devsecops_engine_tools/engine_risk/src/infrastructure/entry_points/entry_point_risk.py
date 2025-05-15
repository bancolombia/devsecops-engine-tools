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
from devsecops_engine_tools.engine_risk.src.domain.usecases.check_threshold import (
    CheckThreshold,
)


from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


def init_engine_risk(
    add_epss_gateway,
    devops_platform_gateway,
    remote_config_source_gateway,
    print_table_gateway,
    dict_args,
    findings,
    services,
    vm_exclusions,
):
    remote_config = remote_config_source_gateway.get_remote_config(
        dict_args["remote_config_repo"],
        "engine_risk/ConfigTool.json",
        dict_args["remote_config_branch"],
    )
    risk_exclusions = remote_config_source_gateway.get_remote_config(
        dict_args["remote_config_repo"],
        "engine_risk/Exclusions.json",
        dict_args["remote_config_branch"],
    )
    pipeline_name = devops_platform_gateway.get_variable("pipeline_name")

    if not findings:
        print("No findings found in Vulnerability Management Platform")
        logger.info("No findings found in Vulnerability Management Platform")
        return

    handle_filters = HandleFilters()

    active_findings = handle_filters.filter(findings)

    unique_findings = handle_filters.filter_duplicated(active_findings)

    filtered_findings, len_tag_filtered = handle_filters.filter_tags_days(
        devops_platform_gateway, remote_config, unique_findings
    )

    data_added = AddData(add_epss_gateway, filtered_findings).process()

    get_exclusions = GetExclusions(
        devops_platform_gateway,
        remote_config_source_gateway,
        dict_args,
        data_added,
        remote_config,
        risk_exclusions,
        services,
        active_findings,
    )
    exclusions, len_new_vuln = get_exclusions.process()

    policy_excluded = len_tag_filtered + len_new_vuln

    threshold = CheckThreshold(
        pipeline_name, remote_config["THRESHOLD"], risk_exclusions
    ).process()

    break_build = BreakBuild(
        devops_platform_gateway,
        print_table_gateway,
        remote_config,
        exclusions,
        vm_exclusions,
        data_added,
        findings,
        threshold,
        policy_excluded,
    )

    return break_build.process()
