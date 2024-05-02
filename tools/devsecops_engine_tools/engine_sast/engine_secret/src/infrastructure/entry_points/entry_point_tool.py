import sys
from devsecops_engine_tools.engine_sast.engine_secret.src.domain.usecases.secret_scan import SecretScan
from devsecops_engine_tools.engine_sast.engine_secret.src.domain.usecases.set_input_core import (
    SetInputCore,
)

def engine_secret_scan(devops_platform_gateway, tool_gateway, dict_args, tool, tool_deserealizator, git_gateway):
    sys.stdout.reconfigure(encoding='utf-8')
    finding_list, config_tool = SecretScan(tool_gateway, devops_platform_gateway, tool_deserealizator, git_gateway).process(dict_args, tool)
    input_core = SetInputCore(devops_platform_gateway, dict_args, tool, config_tool)
    return finding_list, input_core.set_input_core(finding_list)