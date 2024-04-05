import sys
from devsecops_engine_tools.engine_sast.engine_secret.src.domain.usecases.secret_scan import SecretScan

def engine_secret_scan(devops_platform_gateway, tool_gateway, dict_args, tool, tool_deserealizator, git_gateway):
    sys.stdout.reconfigure(encoding='utf-8')
    return SecretScan(tool_gateway, devops_platform_gateway, tool_deserealizator, git_gateway).process(dict_args, tool)