from devsecops_engine_tools.engine_risk.src.infrastructure.entry_points.entry_point_risk import (
    init_engine_risk,
)

from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings


logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


def runner_engine_risk(
    dict_args, findings, devops_platform_gateway, print_table_gateway
):
    try:
        init_engine_risk(
            devops_platform_gateway,
            print_table_gateway,
            dict_args,
            findings,
        )
    except Exception as e:
        logger.error("Error in engine risk: {0} ".format(str(e)))
        raise Exception("Error in engine risk: {0} ".format(str(e)))
