from devsecops_engine_utilities.azuredevops.models.AzureMessageLoggingPipeline import AzureMessageLoggingPipeline
from devsecops_engine_tools.engine_sast.engine_secret.src.domain.model.gateway.tool_gateway import ToolGateway
from devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.entry_points.entry_point_tool import engine_secret_scan

def runner_secret_scan(remote_config_repo, remote_config_path, tool):
    try:
        (
            remote_config_repo,
            remote_config_path,
            tool,
        ) = (
            remote_config_repo,
            remote_config_path,
            tool
        )

        return engine_secret_scan(
            remote_config_repo=remote_config_repo,
            remote_config_path=remote_config_path,
            tool=tool,
        )
    except Exception as e:
        print(
            AzureMessageLoggingPipeline.WarningLogging.get_message(
                "Error SCAN: {0} ".format(str(e))
            )
        )


if __name__ == "__main__":
    runner_secret_scan()