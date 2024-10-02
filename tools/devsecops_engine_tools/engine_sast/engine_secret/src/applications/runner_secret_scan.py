from devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.entry_points.entry_point_tool import (
    engine_secret_scan
    )
from devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.trufflehog.trufflehog_run import (
    TrufflehogRun
    )
from devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.trufflehog.trufflehog_deserealizator import (
    SecretScanDeserealizator
    )
from devsecops_engine_tools.engine_utilities.git_cli.infrastructure.git_run import (
    GitRun
    )

def runner_secret_scan(dict_args, tool, devops_platform_gateway):
    try:
        tool_deserealizator = None
        tool_gateway = None
        git_gateway = GitRun()
        if (tool == "TRUFFLEHOG"):
            tool_gateway = TrufflehogRun()
            tool_deserealizator = SecretScanDeserealizator()
        return engine_secret_scan(
            devops_platform_gateway = devops_platform_gateway,
            tool_gateway = tool_gateway,
            dict_args = dict_args,
            tool=tool,
            tool_deserealizator = tool_deserealizator,
            git_gateway = git_gateway
        )
    except Exception as e:
        raise Exception(f"Error engine_secret : {str(e)}")

if __name__ == "__main__":
    runner_secret_scan()