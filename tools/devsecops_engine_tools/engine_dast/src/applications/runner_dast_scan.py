import json
from typing import List
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
from devsecops_engine_tools.engine_dast.src.infrastructure.driven_adapters.jwt.jwt_tool import (
    JwtTool,
)
from devsecops_engine_tools.engine_dast.src.infrastructure.driven_adapters.oauth.generic_oauth import (
    GenericOauth,
)
from devsecops_engine_tools.engine_dast.src.infrastructure.driven_adapters.http.client.auth_client import (
    AuthClientCredential,
)

from devsecops_engine_tools.engine_dast.src.domain.model.api_config import (
    ApiConfig
)
from devsecops_engine_tools.engine_dast.src.domain.model.api_operation import (
    ApiOperation
)


def runner_engine_dast(dict_args, tool_gateway, secret_tool, other_tools):
    try:
        # Define driven adapters
        # Initialize variables
        devops_platform_gateway = AzureDevops()
        tool_gateway = None # One or more tools
        extra_tools = []
        target_config = None
        
        # Filling operations list with adapters
        with open(dict_args["dast_file_path"], 'r') as dast_file:
            data = json.load(dast_file)
            if "operations" in data: # Api
                operations: List = []
                for elem in data["operations"]:
                    security_type = elem["operation"]["security_auth"]["type"].lower()
                    if security_type == "jwt":
                        operations.append(
                            ApiOperation(
                                elem,
                                JwtObject(
                                    elem["operation"]["security_auth"]
                        )))
                    elif security_type == "oauth":
                        operations.append(
                            ApiOperation(
                                elem,
                                GenericOauth(
                                    elem["operation"]["security_auth"]
                                )
                            )
                        )
                data["operations"] = operations
                target_config = ApiConfig(data)
            else: # Web Application
                pass


        if tool_gateway == "NUCLEI": # tool_gateway is the main Tool
            tool_gateway = NucleiTool()

        if any(k.lower() == "jwt" for k in other_tools.keys()): #Validate if JWT in other tools
            extra_tools.append(JwtTool())

        return init_engine_dast(
            devops_platform_gateway=devops_platform_gateway,
            tool_gateway=tool_gateway,
            dict_args=dict_args,
            secret_tool=secret_tool,
            tool=tool_gateway,
            extra_tools=extra_tools,
            target_data=target_config
        )

    except Exception as e:
        raise Exception(f"Error engine dast : {str(e)}")