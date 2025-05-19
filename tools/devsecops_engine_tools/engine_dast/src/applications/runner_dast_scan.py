from typing import List
from devsecops_engine_tools.engine_dast.src.infrastructure.entry_points.entry_point_dast import (
    init_engine_dast,
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
from devsecops_engine_tools.engine_dast.src.domain.model.wa_config import (
    WaConfig
)
from devsecops_engine_tools.engine_dast.src.infrastructure.helpers.json_handler import (
    load_json_file
)
from devsecops_engine_tools.engine_core.src.domain.model.input_core import (
    InputCore,
)
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()

def runner_engine_dast(dict_args, config_tool, secret_tool, devops_platform_gateway, remote_config_source_gateway):
    try:
        if config_tool["TOOL"].lower() == "nuclei": # tool_gateway is the main Tool
            tool_run = NucleiTool()
        extra_tools = []
        target_config = None

        # Filling operations list with adapters
        data = load_json_file(dict_args["dast_file_path"])

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
                            )
                        )
                    )
                elif security_type == "oauth":
                    operations.append(
                        ApiOperation(
                            elem,
                            GenericOauth(
                                elem["operation"]["security_auth"],
                                data["endpoint"]
                            )
                        )
                    )
                else:
                    operations.append(
                        ApiOperation(
                            elem,
                            AuthClientCredential(
                                elem["operation"]["security_auth"]
                            )
                        )
                    )
            data["operations"] = operations
            target_config = ApiConfig(data)
        elif "WA" in data: # Web Application
            if data["data"].get["security_auth"] == "oauth":
                authentication_gateway =  GenericOauth(
                        data["data"]["security_auth"]
                    )
            target_config = WaConfig(data, authentication_gateway)
        else:
            raise ValueError("Can't match if the target type is an api or a web application")

        if any((k.lower() == "jwt") for k in config_tool["EXTRA_TOOLS"]) and any(isinstance(operation.authentication_gateway, JwtObject) for operation in data["operations"] ):
            extra_tools.append(JwtTool(target_config))

        return init_engine_dast(
            devops_platform_gateway=devops_platform_gateway,
            tool_gateway=tool_run,
            dict_args=dict_args,
            secret_tool=secret_tool,
            config_tool=config_tool,
            extra_tools=extra_tools,
            target_data=target_config
        )
    except Exception as e:
        logger.error(f"Error engine_dast: {e}")
        config_tool_dast = remote_config_source_gateway.get_remote_config(
            dict_args["remote_config_repo"], "engine_dast/ConfigTool.json", dict_args["remote_config_branch"]
        )
        if config_tool_dast["IGNORE_ERRORS"]:
            input_core = InputCore(
                totalized_exclusions=[],
                threshold_defined={},
                path_file_results="",
                custom_message_break_build=config_tool_dast.get("MESSAGE_INFO_DAST"),
                scope_pipeline="",
                scope_service="",
                stage_pipeline=devops_platform_gateway.get_variable("stage"),
            )
            return [], input_core
        else:
            raise Exception(f"Error engine_dast: {e}")
        