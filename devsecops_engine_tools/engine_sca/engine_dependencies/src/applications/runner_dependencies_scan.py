from devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.xray_tool.xray_manager_scan import (
    XrayScan,
)
from devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.xray_tool.xray_deserialize_output import (
    XrayDeserializator,
)
from devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.entry_points.entry_point_tool import (
    init_engine_dependencies,
)


def runner_engine_dependencies(dict_args, config_tool, token, devops_platform_gateway):
    try:
        if config_tool["ENGINE_DEPENDENCIES"]["TOOL"] == "XRAY":
            tool_run = XrayScan()
            tool_deserializator = XrayDeserializator()

        return init_engine_dependencies(
            tool_run,
            devops_platform_gateway,
            tool_deserializator,
            dict_args,
            token,
            config_tool["ENGINE_DEPENDENCIES"]["TOOL"],
        )

    except Exception as e:
        raise Exception(f"Error SCAN engine dependencies : {str(e)}")


if __name__ == "__main__":
    runner_engine_dependencies()
