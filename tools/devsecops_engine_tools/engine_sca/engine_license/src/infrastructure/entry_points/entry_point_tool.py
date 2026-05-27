"""Entry point of the engine_license module.

The flow is intentionally linear and standalone (it does NOT participate
in the build pipeline gating logic):

    1. Always generate a fresh SBOM of the local repository (no cache reuse,
       no branch filter, no image scanning).
    2. Run Grant against that SBOM.
    3. Build the ``{pipeline_name}_LICENSE.json`` artifact from Grant's
       output, applying the policy declared in remote_config.

The entry point returns ``(license_json_path, sbom_components)``.
"""

import os

from devsecops_engine_tools.engine_sca.engine_license.src.domain.usecases.build_license_report import (
    BuildLicenseReport,
)
from devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway import (
    DevopsPlatformGateway,
)
from devsecops_engine_tools.engine_core.src.domain.model.gateway.sbom_manager import (
    SbomManagerGateway,
)
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


def init_engine_license(
    tool_run,
    devops_platform_gateway: DevopsPlatformGateway,
    remote_config_source_gateway: DevopsPlatformGateway,
    dict_args,
    secret_tool,
    config_tool,
    tool_sbom: SbomManagerGateway,
):
    """Run the standalone engine_license flow.

    Returns a tuple ``(license_json_path, sbom_components)``. Either or
    both elements may be ``None`` if the corresponding step failed.
    """
    remote_config = remote_config_source_gateway.get_remote_config(
        dict_args["remote_config_repo"],
        "engine_sca/engine_license/ConfigTool.json",
        dict_args["remote_config_branch"],
    )

    pipeline_name = devops_platform_gateway.get_variable("pipeline_name")
    to_scan = dict_args.get("folder_path") or os.getcwd()

    if not os.path.exists(to_scan):
        logger.error(f"Path {to_scan} does not exist; aborting license scan.")
        return None, None

    config_sbom = config_tool.get("SBOM_MANAGER", {}) or {}
    if tool_sbom is None:
        logger.error("SBOM tool gateway is not configured; aborting license scan.")
        return None, None
    sbom_components = tool_sbom.get_components(to_scan, config_sbom, pipeline_name)
    sbom_path = f"{pipeline_name}_SBOM.json"
    if not os.path.exists(sbom_path):
        logger.error(
            f"SBOM file {sbom_path} not found after generation; aborting license scan."
        )
        return None, sbom_components

    grant_report_path = tool_run.run_tool_license_sca(
        remote_config,
        dict_args,
        None,
        pipeline_name,
        to_scan,
        sbom_path,
        None,
        secret_tool,
    )
    if not grant_report_path:
        logger.error("Grant scan produced no output; aborting LICENSE report build.")
        return None, sbom_components

    license_json_path = BuildLicenseReport().process(
        grant_report_path, remote_config, pipeline_name
    )
    return license_json_path, sbom_components
