from devsecops_engine_tools.engine_sast.engine_iac.src.domain.usecases.iac_scan import (
    IacScan,
)

def init_engine_sast_rm(devops_platform_gateway, tool_gateway, dict_args, secret_tool, tool):
    iac_scan = IacScan(tool_gateway, devops_platform_gateway)
    return iac_scan.process(dict_args, secret_tool, tool)
