from devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.usecases.dependencies_sca_scan import (
    DependenciesScan,
)
from devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.usecases.set_input_core import (
    SetInputCore,
)
from devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.usecases.handle_remote_config_patterns import (
    HandleRemoteConfigPatterns,
)

import os
import sys

from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


def init_engine_dependencies(
    tool_run, tool_remote, tool_deserializator, dict_args, secret_tool, tool
):
    remote_config = tool_remote.get_remote_config(
        dict_args["remote_config_repo"],
        "engine_sca/engine_dependencies/ConfigTool.json",
    )
    exclusions = tool_remote.get_remote_config(
        dict_args["remote_config_repo"],
        "engine_sca/engine_dependencies/Exclusions.json",
    )
    pipeline_name = tool_remote.get_variable("pipeline_name")

    handle_remote_config_patterns = HandleRemoteConfigPatterns(
        remote_config, exclusions, pipeline_name
    )
    skip_flag = handle_remote_config_patterns.skip_from_exclusion()
    scan_flag = handle_remote_config_patterns.ignore_analysis_pattern()

    dependencies_scanned = None
    deserialized = []
    input_core = SetInputCore(remote_config, exclusions, pipeline_name, tool)

    if scan_flag and not (skip_flag):
        to_scan = dict_args["folder_path"] if dict_args["folder_path"] else os.getcwd()
        if os.path.exists(to_scan):
            dependencies_sca_scan = DependenciesScan(
                tool_run,
                tool_deserializator,
                remote_config,
                dict_args,
                exclusions,
                pipeline_name,
                to_scan,
                secret_tool,
            )
            dependencies_scanned = dependencies_sca_scan.process()
            deserialized = (
                dependencies_sca_scan.deserializator(dependencies_scanned)
                if dependencies_scanned is not None
                else []
            )
        else:
            logger.error(f"Path {to_scan} does not exist")
    else:
        print(f"Tool skipped by DevSecOps policy")
        logger.info(f"Tool skipped by DevSecOps policy")

    core_input = input_core.set_input_core(dependencies_scanned)

    return deserialized, core_input
