from devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.azure.azure_remote_config import (
    AzureRemoteConfig,
)
from devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.xray_tool.xray_manager_scan import (
    XrayScan,
)
from devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.xray_tool.xray_deserialize_output import (
    XrayDeserializator,
)
from devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.entry_points.entry_point_tool import (
    init_engine_sca_rm,
)


def runner_engine_dependencies(dict_args, config_tool, token):
    try:
        tool_run = XrayScan()
        tool_deserializator = XrayDeserializator()
        tool_remote = AzureRemoteConfig()
        return init_engine_sca_rm(
            tool_run, tool_remote, tool_deserializator, dict_args, token
        )

    except Exception as e:
        raise Exception(f"Error SCAN engine dependencies : {str(e)}")


if __name__ == "__main__":
    runner_engine_dependencies()
