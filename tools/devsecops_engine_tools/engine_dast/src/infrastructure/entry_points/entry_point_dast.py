# STD libraries

# 3RD party libraries

# local imports
from devsecops_engine_tools.engine_dast.src.domain.usecases.dast_scan import (
    DastScan,
)


def init_engine_dast(
    devops_platform_gateway, 
    tool_gateway, 
    dict_args, 
    secret_tool, 
    tool,
    authentication_gateway_list
):
    dast_scan = DastScan(tool_gateway, devops_platform_gateway, authentication_gateway_list)
    return dast_scan.process(dict_args, secret_tool, tool)
