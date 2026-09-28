from devsecops_engine_tools.engine_sast.engine_scripts.src.infrastructure.entry_points.entry_point_tool import (
    init_engine_sast_rm,
)
from devsecops_engine_tools.engine_sast.engine_scripts.src.infrastructure.driven_adapters.script.script_tool import (
    ScriptTool
)


def runner_engine_scripts(dict_args, tool, secret_tool, devops_platform_gateway, remote_config_source_gateway, env):
    try:
        tool_gateway = None

        tools = {
            "SCRIPT": ScriptTool(),
        }

        if tool in tools:
            tool_gateway = tools[tool]

        findings_list, input_core = init_engine_sast_rm(
            devops_platform_gateway=devops_platform_gateway,
            remote_config_source_gateway=remote_config_source_gateway,
            tool_gateway=tool_gateway,
            dict_args=dict_args,
            secret_tool=secret_tool,
            tool=tool,
            env=env,
        )

        return findings_list, input_core

    except Exception as e:
        raise RuntimeError(f"Error engine_scripts : {str(e)}") from e
