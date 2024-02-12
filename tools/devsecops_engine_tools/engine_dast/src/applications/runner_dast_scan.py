from devsecops_engine_tools.engine_dast.src.infrastructure.entry_points.entry_point_dast import (
    init_engine_dast,
)
from devsecops_engine_tools.engine_dast.src.infrastructure.driven_adapters.azure.azure_devops import (
    AzureDevops,
)
from devsecops_engine_tools.engine_dast.src.infrastructure.driven_adapters.nuclei.nuclei_tool import (
    NucleiTool,
)
from devsecops_engine_tools.engine_dast.src.infrastructure.driven_adapters.jwt.jwt_object import (
    JwtObject,
)
from devsecops_engine_tools.engine_dast.src.infrastructure.driven_adapters.oauth.azure_active_directory import (
    AzureActiveDirectory,
)


def runner_engine_dast(dict_args, tool, secret_tool):
    try:
        devops_platform_gateway = AzureDevops()
        tool_gateway = None
        auth_method = ""
        if tool == "NUCLEI":
            tool_gateway = NucleiTool()

        if auth_method.lower() == "jwt":
            authentication_gateway = JwtObject()
        elif auth_method.lower() == "oauth":
            authentication_gateway = AzureActiveDirectory()


        return init_engine_dast(
            devops_platform_gateway=devops_platform_gateway,
            tool_gateway=tool_gateway,
            dict_args=dict_args,
            secret_tool=secret_tool,
            tool=tool,
            authentication_gateway=authentication_gateway
        )

    except Exception as e:
        raise Exception(f"Error engine dast : {str(e)}")


if __name__ == "__main__":
    runner_engine_dast()
