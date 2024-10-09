# STD libraries

# 3RD party libraries

# Local imports
from devsecops_engine_tools.engine_dast.src.domain.usecases.dast_scan import (
    DastScan,
)

def init_engine_dast(
    devops_platform_gateway,
    tool_gateway,
    dict_args,
    checks_token,
    config_tool,
    extra_tools,
    target_data
):
    dast_scan = DastScan(tool_gateway, devops_platform_gateway, target_data, extra_tools)
    return dast_scan.process(dict_args, checks_token, config_tool)
