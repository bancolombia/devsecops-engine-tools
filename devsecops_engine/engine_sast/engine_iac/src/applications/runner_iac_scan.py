import sys
from engine_sast.engine_iac.src.infrastructure.entry_points.entry_point_tool import (
    get_inputs_from_cli,
    get_inputs_from_config_file,
    init_engine_sast_rm,
)
from devsecops_engine_utilities.azuredevops.models.AzureMessageLoggingPipeline import AzureMessageResultPipeline


def main():
    try:
        (
            remote_config_repo,
            remote_config_path,
            tool,
        ) = (
            get_inputs_from_cli(sys.argv[1:]) or get_inputs_from_config_file()
        )
        init_engine_sast_rm(
            remote_config_repo=remote_config_repo,
            remote_config_path=remote_config_path,
            tool=tool,
        )

    except Exception as e:
        error_message = str(e)
        print(f"Error SCAN : {error_message}")
        print(AzureMessageResultPipeline.Succeeded.value)
        # Manejar el error según sea necesario


if __name__ == "__main__":
    main()
