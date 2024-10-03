import sys
from devsecops_engine_tools.engine_sast.engine_secret.src.domain.usecases.secret_scan import SecretScan
from devsecops_engine_tools.engine_sast.engine_secret.src.domain.usecases.set_input_core import (
    SetInputCore,
)

def engine_secret_scan(devops_platform_gateway, tool_gateway, dict_args, tool, tool_deserealizator, git_gateway, secret_tool):
    exclusions = devops_platform_gateway.get_remote_config(
        dict_args["remote_config_repo"], "engine_sast/engine_secret/Exclusions.json"
    )
    secret_scan = SecretScan(tool_gateway, devops_platform_gateway, tool_deserealizator, git_gateway)
    config_tool = secret_scan.complete_config_tool(dict_args, tool)
    skip_tool = secret_scan.skip_from_exclusion(exclusions)
    finding_list, file_path_findings = secret_scan.process(skip_tool, config_tool, secret_tool, dict_args)
    input_core = SetInputCore(devops_platform_gateway, dict_args, tool, config_tool)
    return finding_list, input_core.set_input_core(file_path_findings)