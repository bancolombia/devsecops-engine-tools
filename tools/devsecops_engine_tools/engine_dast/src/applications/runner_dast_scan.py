import json
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
from devsecops_engine_tools.engine_dast.src.infrastructure.driven_adapters.oauth.generic_oauth import (
    GenericOauth,
)
from devsecops_engine_tools.engine_dast.src.infrastructure.driven_adapters.http.client.auth_client import (
    AuthClientCredential,
)

def runner_engine_dast(dict_args, tool, secret_tool):
    try:
        # Define driven adapters
        # Initialize variables
        devops_platform_gateway = AzureDevops()
        tool_gateway = None
        authentication_list: list = []

        # Filling authentication list preserving the order
        with open(dict_args["dast_file_path"], 'r') as dast_file:
            data = json.load(dast_file)
            for elem in data["operations"]:
                if elem["operation"]["security_auth"]["type"] == "jwt":
                    authentication_list.append(JwtObject(elem.get("operation").get("security_auth")))
                elif elem["operation"]["security_auth"]["type"] == "oauth":
                    authentication_list.append(GenericOauth(elem.get("operation").get("security_auth")))
                elif elem["operation"]["security_auth"]["type"] == "client_secret":
                    authentication_list.append(AuthClientCredential(elem.get("operation").get("security_auth")))


        if tool == "NUCLEI":
            tool_gateway = NucleiTool()

        return init_engine_dast(
            devops_platform_gateway=devops_platform_gateway,
            tool_gateway=tool_gateway,
            dict_args=dict_args,
            secret_tool=secret_tool,
            tool=tool,
            authentication_gateway_list=authentication_list
        )

    except Exception as e:
        raise Exception(f"Error engine dast : {str(e)}")


if __name__ == "__main__":
    runner_engine_dast()
