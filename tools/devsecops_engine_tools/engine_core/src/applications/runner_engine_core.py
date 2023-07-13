from devsecops_engine_tools.engine_sast.engine_iac.src.applications.runner_iac_scan import runner_engine_iac
from devsecops_engine_utilities.azuredevops.models.AzureMessageLoggingPipeline import AzureMessageResultPipeline


def main():
    try:
        print(runner_engine_iac())
    except Exception as e:
        print(f"Error SCAN : {str(e)}")
        print(AzureMessageResultPipeline.Succeeded.value)
        # Manejar el error según sea necesario


if __name__ == "__main__":
    main()
