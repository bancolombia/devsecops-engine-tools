import json

from devsecops_engine_tools.engine_core.src.domain.model.finding import (
    Finding,
    Category,
)
from devsecops_engine_tools.engine_core.src.domain.model.input_core import InputCore
from devsecops_engine_tools.engine_core.src.domain.model.threshold import Threshold
from devsecops_engine_tools.engine_sca.engine_license.src.infrastructure.entry_points.entry_point_tool import (
    init_engine_license,
)

_RELEVANT_POLICIES = ("fail", "warn")
_DEFAULT_COMPLIANCE_THRESHOLD = {"Critical": 1}

def _build_findings_from_license_json(license_json_path):
    if not license_json_path:
        return []
    with open(license_json_path, "r") as fh:
        data = json.load(fh)
    findings = []
    for dep in data.get("dependencies", []):
        policy = dep.get("policy_applied", "")
        if policy not in _RELEVANT_POLICIES:
            continue
        name = dep.get("name", "unknown")
        version = dep.get("version", "")
        license_label = dep.get("license_matched") or (dep.get("licenses", []) or ["UNKNOWN"])[0]
        findings.append(
            Finding(
                id=f"{license_label}-{name}",
                cvss="",
                where=f"{name}:{version}",
                description=f"License '{license_label}' for package '{name}' ({dep.get('policy_reason', '')}). ",
                severity=dep.get("severity", "info"),
                identification_date="",
                published_date_cve="",
                module="engine_license",
                category=Category.COMPLIANCE,
                requirements="",
                tool="CDXGEN",
            )
        )
    return findings


def runner_engine_license(
    dict_args,
    config_tool,
    secret_tool,
    devops_platform_gateway,
    remote_config_source_gateway,
    sbom_tool_gateway,
):
    """Run the engine_license standalone flow.

    Produces ''{pipeline_name}_LICENSE.json''  in the CWD.

    Returns:
        Tuple ''{findings_list, input_core, sbom_components}''.
    """
    try:
        license_json_path, sbom_components, remote_config = init_engine_license(
            devops_platform_gateway,
            remote_config_source_gateway,
            dict_args,
            config_tool,
            sbom_tool_gateway,
        )

        pipeline_name = devops_platform_gateway.get_variable("pipeline_name")
        findings_list = _build_findings_from_license_json(license_json_path)

        threshold_data = (remote_config or {}).get("THRESHOLD", {})
        input_core = InputCore(
            totalized_exclusions=[],
            threshold_defined=Threshold({
                "VULNERABILITY": threshold_data.get("VULNERABILITY", {}),
                "COMPLIANCE": threshold_data.get("COMPLIANCE", _DEFAULT_COMPLIANCE_THRESHOLD),
            }),
            path_file_results=license_json_path,
            custom_message_break_build="License scan completed",
            scope_pipeline=pipeline_name,
            scope_service=pipeline_name,
            stage_pipeline="Build",
        )

        return findings_list, input_core, sbom_components

    except Exception as e:
        raise Exception(f"Error SCAN engine license : {str(e)}")


if __name__ == "__main__":
    runner_engine_license()
