from devsecops_engine_tools.engine_sast.engine_code.src.infrastructure.entry_points.entry_point_tool import (
    init_engine_sast_code,
)
from devsecops_engine_tools.engine_sast.engine_code.src.infrastructure.driven_adapters.bearer.bearer_tool import (
    BearerTool
)
from devsecops_engine_tools.engine_utilities.git_cli.infrastructure.git_run import (
    GitRun
)

def runner_engine_code(dict_args, tool, devops_platform_gateway, remote_config_source_gateway):
    try:
        tool_gateway = None
        git_gateway = GitRun()
        if (tool == "BEARER"):
            tool_gateway = BearerTool()

        return init_engine_sast_code(
            devops_platform_gateway=devops_platform_gateway,
            remote_config_source_gateway=remote_config_source_gateway,
            tool_gateway=tool_gateway,
            dict_args=dict_args,
            git_gateway=git_gateway,
            tool=tool,
        )

    except Exception as e:
        raise Exception(f"Error engine_code : {str(e)}")


if __name__ == "__main__":
    runner_engine_code()
