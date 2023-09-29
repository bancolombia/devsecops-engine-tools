import sys
from devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.entry_points.entry_point_tool import (
    get_inputs_from_cli,
    get_inputs_from_config_file,
    init_engine_sast_rm,
)
from devsecops_engine_utilities.azuredevops.models.AzureMessageLoggingPipeline import AzureMessageResultPipeline


def runner_engine_iac():
    try:
        (
            remote_config_repo,
            remote_config_path,
            tool,
            environment,
        ) = (
            get_inputs_from_cli(sys.argv[1:]) or get_inputs_from_config_file()
        )
        return init_engine_sast_rm(
            remote_config_repo=remote_config_repo,
            remote_config_path=remote_config_path,
            tool=tool,
            environment=environment,
        )

    except Exception as e:
        print(AzureMessageResultPipeline.Succeeded.value)
        raise Exception(f"Error SCAN : {str(e)}")
        # Manejar el error según sea necesario


if __name__ == "__main__":
    runner_engine_iac()