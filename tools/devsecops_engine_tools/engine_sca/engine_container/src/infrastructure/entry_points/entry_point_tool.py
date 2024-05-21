from devsecops_engine_tools.engine_sca.engine_container.src.domain.usecases.container_sca_scan import (
    ContainerScaScan,
)
from devsecops_engine_tools.engine_sca.engine_container.src.domain.usecases.handle_remote_config_patterns import (
    HandleRemoteConfigPatterns,
)
from devsecops_engine_tools.engine_sca.engine_container.src.domain.usecases.set_input_core import (
    SetInputCore,
)


def init_engine_sca_rm(
    tool_run,
    tool_remote,
    tool_images,
    tool_deseralizator,
    dict_args,
    token,
    config_tool,
):
    remote_config = tool_remote.get_remote_config(
        dict_args["remote_config_repo"], "engine_sca/engine_container/ConfigTool.json"
    )
    exclusions = tool_remote.get_remote_config(
        dict_args["remote_config_repo"], "engine_sca/engine_container/Exclusions.json"
    )
    pipeline_name = tool_remote.get_variable("pipeline_name")
    handle_remote_config_patterns = HandleRemoteConfigPatterns(
        remote_config, exclusions, pipeline_name
    )
    skip_flag = handle_remote_config_patterns.skip_from_exclusion()
    scan_flag = handle_remote_config_patterns.ignore_analysis_pattern()
    build_id = tool_remote.get_variable("build_id")
    images_scanned = []
    deseralized = []
    if scan_flag and not (skip_flag):
        container_sca_scan = ContainerScaScan(
            tool_run,
            remote_config,
            tool_images,
            tool_deseralizator,
            build_id,
            token,
        )
        images_scanned = container_sca_scan.process()
        deseralized = container_sca_scan.deseralizator(images_scanned)
    input_core = SetInputCore(tool_remote, dict_args, config_tool)

    return deseralized, input_core.set_input_core(images_scanned)
