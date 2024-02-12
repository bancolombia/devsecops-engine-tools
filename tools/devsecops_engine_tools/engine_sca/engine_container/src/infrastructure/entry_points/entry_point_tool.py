from devsecops_engine_tools.engine_sca.engine_container.src.domain.usecases.container_sca_scan import (
    ContainerScaScan,
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
    container_sca_scan = ContainerScaScan(
        tool_run, tool_remote, tool_images, tool_deseralizator, dict_args, token
    )
    input_core = SetInputCore(tool_remote, dict_args, config_tool)
    images_scanned = container_sca_scan.process()

    return container_sca_scan.deseralizator(images_scanned), input_core.set_input_core(
        images_scanned
    )
