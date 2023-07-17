from devsecops_engine_tools.engine_core.src.infrastructure.entry_points.entry_point_core import init_engine_core
from devsecops_engine_utilities.azuredevops.models.AzureMessageLoggingPipeline import AzureMessageResultPipeline


def main():
    try:
        init_engine_core()
    except Exception as e:
        print(f"Error SCAN : {str(e)}")
        #print(AzureMessageResultPipeline.Succeeded.value)
        # Manejar el error según sea necesario


if __name__ == "__main__":
    main()
