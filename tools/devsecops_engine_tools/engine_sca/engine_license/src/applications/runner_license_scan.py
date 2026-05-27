from devsecops_engine_tools.engine_core.src.domain.model.input_core import InputCore
from devsecops_engine_tools.engine_core.src.domain.model.threshold import Threshold
from devsecops_engine_tools.engine_sca.engine_license.src.infrastructure.driven_adapters.grant_tool.grant_manager_scan import (
    GrantScan,
)
from devsecops_engine_tools.engine_sca.engine_license.src.infrastructure.entry_points.entry_point_tool import (
    init_engine_license,
)


def runner_engine_license(
    dict_args,
    config_tool,
    secret_tool,
    devops_platform_gateway,
    remote_config_source_gateway,
    sbom_tool_gateway,
):
    """Run the engine_license standalone flow.

    Produces ``{pipeline_name}_LICENSE.json`` in the CWD and assembles a
    minimal :class:`InputCore` so downstream consumers (BreakBuild,
    MetricsManager) keep working without participating in vulnerability
    management or risk scoring.

    Returns:
        Tuple ``(findings_list, input_core, sbom_components)`` mirroring
        the contract used by other engine runners. ``findings_list`` is
        always empty because engine_license is a standalone artifact
        generator; severity decisions live inside the LICENSE.json.
    """
    try:
        tools_mapping = {
            "GRANT": {
                "tool_run": GrantScan,
                "tool_sbom": sbom_tool_gateway,
            }
        }

        selected_tool = config_tool["ENGINE_LICENSE"]["TOOL"]
        tool_run = tools_mapping[selected_tool]["tool_run"]()
        tool_sbom = tools_mapping[selected_tool]["tool_sbom"]

        license_json_path, sbom_components = init_engine_license(
            tool_run,
            devops_platform_gateway,
            remote_config_source_gateway,
            dict_args,
            secret_tool,
            config_tool,
            tool_sbom,
        )

        pipeline_name = devops_platform_gateway.get_variable("pipeline_name")
        input_core = InputCore(
            totalized_exclusions=[],
            threshold_defined=Threshold({"VULNERABILITY": {}, "COMPLIANCE": {}}),
            path_file_results=license_json_path,
            custom_message_break_build="License scan completed",
            scope_pipeline=pipeline_name,
            scope_service=pipeline_name,
            stage_pipeline="Build",
        )

        return [], input_core, sbom_components

    except Exception as e:
        raise Exception(f"Error SCAN engine license : {str(e)}")


if __name__ == "__main__":
    runner_engine_license()
