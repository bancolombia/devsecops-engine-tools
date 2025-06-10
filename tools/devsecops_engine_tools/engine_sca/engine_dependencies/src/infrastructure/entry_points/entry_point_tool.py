from devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.usecases.dependencies_sca_scan import (
    DependenciesScan,
)
from devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.usecases.set_input_core import (
    SetInputCore,
)
from devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.usecases.handle_remote_config_patterns import (
    HandleRemoteConfigPatterns,
)
from devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway import (
    DevopsPlatformGateway,
)
from devsecops_engine_tools.engine_core.src.domain.model.gateway.sbom_manager import (
    SbomManagerGateway,
)

import os

from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


def init_engine_dependencies(
    tool_run,
    tool_remote: DevopsPlatformGateway,
    remote_config_source_gateway: DevopsPlatformGateway,
    tool_deserializator,
    dict_args,
    secret_tool,
    config_tool,
    tool_sbom: SbomManagerGateway,
):
    remote_config = remote_config_source_gateway.get_remote_config(
        dict_args["remote_config_repo"],
        "engine_sca/engine_dependencies/ConfigTool.json",
        dict_args["remote_config_branch"]
    )
    exclusions = remote_config_source_gateway.get_remote_config(
        dict_args["remote_config_repo"],
        "engine_sca/engine_dependencies/Exclusions.json",
        dict_args["remote_config_branch"]
    )
    pipeline_name = tool_remote.get_variable("pipeline_name")
    build_id = tool_remote.get_variable("build_id")
    build_url = tool_remote.get_build_pipeline_execution_url()

    handle_remote_config_patterns = HandleRemoteConfigPatterns(
        remote_config, exclusions, pipeline_name
    )
    skip_flag = handle_remote_config_patterns.skip_from_exclusion()
    scan_flag = handle_remote_config_patterns.ignore_analysis_pattern()

    dependencies_scanned = None
    deserialized = []
    sbom_components = None
    config_sbom = config_tool["SBOM_MANAGER"]
    input_core = SetInputCore(
        remote_config,
        exclusions,
        pipeline_name,
        config_tool["ENGINE_DEPENDENCIES"]["TOOL"],
    )

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
                build_id,
                build_url

            )
            if config_sbom["ENABLED"] and any(
                branch in str(tool_remote.get_variable("branch_tag"))
                for branch in config_sbom["BRANCH_FILTER"]
            ):
                sbom_components = tool_sbom.get_components(
                    to_scan,
                    config_sbom,
                    pipeline_name
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
        print("Tool skipped by DevSecOps policy")
        dict_args["send_metrics"] = "false"
        dict_args["use_vulnerability_management"] = "false"

    core_input = input_core.set_input_core(dependencies_scanned)

    return deserialized, core_input, sbom_components
