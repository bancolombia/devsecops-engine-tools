from devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.entry_points.entry_point_tool import engine_secret_scan
from devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.azure_devops.azure_devops import AzureDevops
from devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.trufflehog.trufflehog_run import TrufflehogRun
from devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.trufflehog.trufflehog_deserealizator import SecretScanDeserealizator

def runner_secret_scan(dict_args, tool):
    try:
        devops_platform_gateway = AzureDevops()
        tool_deserealizator = SecretScanDeserealizator()
        tool_gateway = None
        if (tool == "TRUFFLEHOG"):
            tool_gateway = TrufflehogRun()
        return engine_secret_scan(
            devops_platform_gateway = devops_platform_gateway,
            tool_gateway = tool_gateway,
            dict_args = dict_args,
            tool=tool,
            tool_deserealizator = tool_deserealizator,
        )
    except Exception as e:
        raise Exception(f"Error engine_secret : {str(e)}")

if __name__ == "__main__":
    runner_secret_scan()