from devsecops_engine_tools.engine_core.src.infrastructure.entry_points.entry_point_core import (
    init_engine_core,
)
from devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.defect_dojo.DefectDojo import (
    DefectDojoPlatform,
)
from devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.checkov.CheckovDeserealizator import (
    CheckovDeserealizator,
)
from devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.aws.secrets_manager import (
    SecretsManager,
)
from devsecops_engine_utilities.azuredevops.models.AzureMessageLoggingPipeline import (
    AzureMessageLoggingPipeline,
)


def application_core():
    try:
        # Define driven adapters for gateways
        vulnerability_management_gateway = DefectDojoPlatform()
        deserializer_gateway = CheckovDeserealizator()
        secrets_manager_gateway = SecretsManager()

        init_engine_core(
            vulnerability_management_gateway,
            deserializer_gateway,
            secrets_manager_gateway,
        )
    except Exception as e:
        print(
            AzureMessageLoggingPipeline.WarningLogging.get_message(
                "Error SCAN: {0} ".format(str(e))
            )
        )


if __name__ == "__main__":
    application_core()
