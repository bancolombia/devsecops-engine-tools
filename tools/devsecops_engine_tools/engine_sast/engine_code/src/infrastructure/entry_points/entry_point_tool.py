from devsecops_engine_tools.engine_sast.engine_code.src.domain.usecases.code_scan import (
    CodeScan,
)

def init_engine_sast_code(devops_platform_gateway, remote_config_source_gateway, tool_gateway, dict_args, git_gateway, tool):
    return CodeScan(tool_gateway, devops_platform_gateway, remote_config_source_gateway, git_gateway).process(dict_args, tool)
