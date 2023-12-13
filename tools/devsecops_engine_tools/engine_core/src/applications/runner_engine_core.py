from devsecops_engine_tools.engine_core.src.infrastructure.entry_points.entry_point_core import (
    init_engine_core,
)
from devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.defect_dojo.DefectDojo import (
    DefectDojoPlatform,
)
from devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.aws.secrets_manager import (
    SecretsManager,
)
from devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.azure.azure_devops import (
    AzureDevops,
)
from devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.print_pretty_table.print_pretty_table import (
    PrintPrettyTable,
)


def application_core():
    try:
        # Define driven adapters for gateways
        vulnerability_management_gateway = DefectDojoPlatform()
        secrets_manager_gateway = SecretsManager()
        devops_platform_gateway = AzureDevops()
        print_table_gateway = PrintPrettyTable()

        init_engine_core(
            vulnerability_management_gateway,
            secrets_manager_gateway,
            devops_platform_gateway,
            print_table_gateway
        )
    except Exception as e:
        print(
            devops_platform_gateway.logging(
                "warning", "Error SCAN: {0} ".format(str(e))
            )
        )


if __name__ == "__main__":
    application_core()
