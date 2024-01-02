from devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.entry_points.entry_point_tool import (
    init_engine_sast_rm,
)
from devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.azure.azure_devops import (
    AzureDevops,
)
from devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.checkov.checkov_tool import (
    CheckovTool
)


def runner_engine_iac(dict_args, tool, secret_tool):
    try:
        # Define driven adapters for gateways
        devops_platform_gateway = AzureDevops()
        tool_gateway = None
        if (tool == "CHECKOV"):
            tool_gateway = CheckovTool()

        return init_engine_sast_rm(
            devops_platform_gateway=devops_platform_gateway,
            tool_gateway=tool_gateway,
            dict_args=dict_args,
            secret_tool=secret_tool,
        )

    except Exception as e:
        raise Exception(f"Error engine_iac : {str(e)}")


if __name__ == "__main__":
    runner_engine_iac()
