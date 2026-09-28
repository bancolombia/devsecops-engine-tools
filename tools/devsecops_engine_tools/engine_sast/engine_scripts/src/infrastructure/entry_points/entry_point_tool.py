from devsecops_engine_tools.engine_sast.engine_scripts.src.domain.usecases.script_scan import (
    ScriptScan,
)


def init_engine_sast_rm(
    devops_platform_gateway,
    remote_config_source_gateway,
    tool_gateway,
    dict_args,
    secret_tool,
    tool,
    env,
):
    return ScriptScan(
        tool_gateway,
        devops_platform_gateway,
        remote_config_source_gateway,
    ).process(dict_args, secret_tool, tool, env)
