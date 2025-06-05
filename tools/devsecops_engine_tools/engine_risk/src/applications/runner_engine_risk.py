from devsecops_engine_tools.engine_risk.src.infrastructure.driven_adapters.first_csv.first_epss_csv import (
    FirstCsv,
)
from devsecops_engine_tools.engine_risk.src.infrastructure.entry_points.entry_point_risk import (
    init_engine_risk,
)

from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings


logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


def runner_engine_risk(
    dict_args,
    findings,
    vm_exclusions,
    services,
    devops_platform_gateway,
    remote_config_source_gateway,
    print_table_gateway,
):
    add_epss_gateway = FirstCsv()

    return init_engine_risk(
        add_epss_gateway,
        devops_platform_gateway,
        remote_config_source_gateway,
        print_table_gateway,
        dict_args,
        findings,
        services,
        vm_exclusions,
    )
