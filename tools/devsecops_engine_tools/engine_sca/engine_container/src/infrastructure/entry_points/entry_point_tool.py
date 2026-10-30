from devsecops_engine_tools.engine_sca.engine_container.src.domain.usecases.container_sca_scan import (
    ContainerScaScan,
)
from devsecops_engine_tools.engine_sca.engine_container.src.domain.usecases.handle_remote_config_patterns import (
    HandleRemoteConfigPatterns,
)
from devsecops_engine_tools.engine_sca.engine_container.src.domain.usecases.set_input_core import (
    SetInputCore,
)
from devsecops_engine_tools.engine_sca.engine_container.src.domain.usecases.get_cross_approval_exclusions import (
    GetCrossApprovalExclusions,
)
from devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.defect_dojo.cross_approval_adapter import (
    DefectDojoCrossApprovalAdapter,
)
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings
import re

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


def init_engine_sca_rm(
    tool_run,
    tool_remote,
    remote_config_source_gateway,
    tool_images,
    tool_deseralizator,
    dict_args,
    secret_tool,
    tool,
):
    remote_config = remote_config_source_gateway.get_remote_config(
        dict_args["remote_config_repo"],
        "engine_sca/engine_container/ConfigTool.json",
        dict_args["remote_config_branch"],
    )
    exclusions = remote_config_source_gateway.get_remote_config(
        dict_args["remote_config_repo"],
        "engine_sca/engine_container/Exclusions.json",
        dict_args["remote_config_branch"],
    )
    pipeline_name = tool_remote.get_variable("pipeline_name")
    regex_clean = remote_config.get("REGEX_CLEAN_END_PIPELINE_NAME")
    if regex_clean:
        pattern = re.compile(regex_clean)
        match = pattern.match(pipeline_name)
        if match:
            pipeline_name= match.group(1)
            
    handle_remote_config_patterns = HandleRemoteConfigPatterns(
        remote_config, exclusions, pipeline_name
    )
    skip_flag = handle_remote_config_patterns.skip_from_exclusion()
    scan_flag = handle_remote_config_patterns.ignore_analysis_pattern()
    branch = tool_remote.get_variable("branch_tag")
    stage = tool_remote.get_variable("stage")
    image_to_scan = dict_args["image_to_scan"]
    image_scanned = None
    base_image = None
    sbom_components = None
    deseralized = []
    cross_approval_exclusions = []
    debug_pipeline_enabled = False
    if scan_flag and not (skip_flag):
        host_defect_dojo = None
        if remote_config.get("CROSS_APPROVAL_EXCLUSIONS", {}).get("ENABLED", False):
            core_config_tool = remote_config_source_gateway.get_remote_config(
                dict_args["remote_config_repo"],
                "engine_core/ConfigTool.json",
                dict_args["remote_config_branch"],
            )
            host_defect_dojo = core_config_tool.get("VULNERABILITY_MANAGER", {}).get(
                "DEFECT_DOJO", {}
            ).get("HOST_DEFECT_DOJO")
        cross_approval_exclusions = GetCrossApprovalExclusions(
            DefectDojoCrossApprovalAdapter()
        ).execute(remote_config, dict_args, secret_tool, host_defect_dojo)
        debug_pipeline_config = remote_config.get("DEBUG_PIPELINE", {})
        debug_pipelines = debug_pipeline_config.get("PIPELINES", [])
        if (
            debug_pipeline_config.get("ENABLED", False)
            and isinstance(debug_pipelines, (list, tuple))
            and pipeline_name in debug_pipelines
        ):
            debug_pipeline_enabled = True
            logger.info(
                "Container debug enabled for pipeline %s. Cross-approval exclusions: %s",
                pipeline_name,
                [
                    {
                        "id": exclusion.id,
                        "where": exclusion.where,
                        "create_date": exclusion.create_date,
                        "expired_date": exclusion.expired_date,
                        "severity": exclusion.severity,
                        "priority": exclusion.priority,
                        "hu": exclusion.hu,
                        "reason": exclusion.reason,
                        "images": exclusion.check_in_desc,
                    }
                    for exclusion in cross_approval_exclusions
                ],
            )
        container_sca_scan = ContainerScaScan(
            tool_run,
            remote_config,
            tool_images,
            tool_deseralizator,
            branch,
            secret_tool,
            dict_args["token_engine_container"],
            image_to_scan,
            exclusions,
            pipeline_name,
            context=dict_args["context"],
            docker_address=dict_args["docker_address"],
            cross_approval_exclusions=cross_approval_exclusions,
        )
        image_scanned, base_image, sbom_components = container_sca_scan.process()
        if image_scanned:
            deseralized = container_sca_scan.deseralizator(image_scanned)
    else:
        print("Tool skipped by DevSecOps policy")
        dict_args["send_metrics"] = "false"
        dict_args["use_vulnerability_management"] = "false"

    input_core = SetInputCore(
        remote_config,
        exclusions,
        pipeline_name,
        tool,
        stage,
        cross_approval_exclusions,
        debug_pipeline_enabled,
    )
    core_input = input_core.set_input_core(image_scanned, base_image)

    return deseralized, core_input, sbom_components
