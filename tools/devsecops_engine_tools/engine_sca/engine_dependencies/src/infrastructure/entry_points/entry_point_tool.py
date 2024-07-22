from devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.usecases.dependencies_sca_scan import (
    DependenciesScan,
)
from devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.usecases.set_input_core import (
    SetInputCore,
)
from devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.usecases.handle_remote_config_patterns import (
    HandleRemoteConfigPatterns,
)
from devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.usecases.find_artifacts import (
    FindArtifacts,
)

import os
import sys

from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


def init_engine_dependencies(
    tool_run, tool_remote, tool_deserializator, dict_args, token, tool
):
    sys.stdout.reconfigure(encoding="utf-8")

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
        bypass_limits_flag = handle_remote_config_patterns.bypass_archive_limits()
        pattern = handle_remote_config_patterns.excluded_files()

        find_artifacts = FindArtifacts(
            os.getcwd(), pattern, remote_config["PACKAGES_TO_SCAN"]
        )
        file_to_scan = find_artifacts.find_artifacts()
        if file_to_scan:
            dependencies_sca_scan = DependenciesScan(
                tool_run,
                tool_deserializator,
                remote_config,
                file_to_scan,
                bypass_limits_flag,
                token,
            )
            dependencies_scanned = dependencies_sca_scan.process()
            deserialized = dependencies_sca_scan.deserializator(dependencies_scanned)
    else:
        print(f"Tool skipped by DevSecOps policy")
        logger.info(f"Tool skipped by DevSecOps policy")

    core_input = input_core.set_input_core(dependencies_scanned)

    return deserialized, core_input
