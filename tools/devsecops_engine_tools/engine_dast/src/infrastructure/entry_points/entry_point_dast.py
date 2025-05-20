from devsecops_engine_tools.engine_dast.src.domain.usecases.dast_scan import (
    DastScan,
)

def init_engine_dast(
    devops_platform_gateway,
    remote_config_source_gateway,
    tool_gateway,
    dict_args,
    secret_tool,
    config_tool,
    extra_tools,
    target_data
):
    dast_scan = DastScan(tool_gateway, devops_platform_gateway, remote_config_source_gateway, target_data, extra_tools)
    return dast_scan.process(dict_args, secret_tool, config_tool)