import re
from devsecops_engine_tools.engine_sca.engine_function.src.domain.usecases.function_sca_scan import (
    FunctionScaScan,
)
from devsecops_engine_tools.engine_sca.engine_function.src.domain.usecases.handle_remote_config_patterns import (
    HandleRemoteConfigPatterns,
)
from devsecops_engine_tools.engine_sca.engine_function.src.domain.usecases.set_input_core import (
    SetInputCore,
)


def init_engine_sca_rm(
    tool_run,
    tool_remote,
    remote_config_source_gateway,
    tool_deseralizator,
    dict_args,
    secret_tool,
    config_tool,
):
    remote_config = remote_config_source_gateway.get_remote_config(
        dict_args["remote_config_repo"],
        "engine_sca/engine_function/ConfigTool.json",
        dict_args["remote_config_branch"],
    )
    exclusions = remote_config_source_gateway.get_remote_config(
        dict_args["remote_config_repo"],
        "engine_sca/engine_function/Exclusions.json",
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
    if scan_flag and not (skip_flag):
        function_sca_scan = FunctionScaScan(
            tool_run,
            remote_config,
            tool_remote,
            tool_deseralizator,
            dict_args,
            secret_tool,
            dict_args["token_engine_container"],
        )
    else:
        print("Tool skipped by DevSecOps policy")
        dict_args["send_metrics"] = "false"
        dict_args["use_vulnerability_management"] = "false"
    input_core = SetInputCore(tool_remote, dict_args, config_tool)
    function_scan = function_sca_scan.process()

    return function_sca_scan.deseralizator(function_scan), input_core.set_input_core()
