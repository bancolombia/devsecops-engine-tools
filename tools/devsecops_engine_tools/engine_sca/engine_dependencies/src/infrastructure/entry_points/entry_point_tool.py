from devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.usecases.dependencies_sca_scan import (
    DependenciesScan,
)
from devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.usecases.set_input_core import (
    SetInputCore,
)
from devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.usecases.handle_excluded_files import (
    HandleExcludedFiles,
)


def init_engine_dependencies(
    tool_run, tool_remote, tool_deserializator, dict_args, token, tool
):
    dependencies_sca_scan = DependenciesScan(
        tool_run, tool_remote, tool_deserializator, dict_args, token
    )
    input_core = SetInputCore(tool_remote, dict_args, tool)
    handle_excluded_files = HandleExcludedFiles(tool_remote, dict_args)
    dependencies_scanned = dependencies_sca_scan.process(
        handle_excluded_files.process()
    )
    deserialized = dependencies_sca_scan.deserializator(dependencies_scanned)
    core_input = input_core.set_input_core(dependencies_scanned)

    return deserialized, core_input
