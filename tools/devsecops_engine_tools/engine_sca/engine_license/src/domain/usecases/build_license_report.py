"""Use case that builds the LICENSE.json artifact from a CycloneDX SBOM.

The output is a hybrid JSON: top-level ``metadata`` block (pipeline name,
scan date, tool, applied policy echo, summary counts) plus a flat
``dependencies`` array listing every package found in the SBOM with its
license(s) and the policy decision.

The artifact is written to ``{pipeline_name}_LICENSE.json`` in the chosen
output directory (CWD by default).
"""

import copy
import json
import os
from datetime import datetime

from devsecops_engine_tools.engine_sca.engine_license.src.domain.usecases.license_policy import (
    build_policy_from_remote_config,
    classify_package,
)
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()

TOOL = "CDXGEN"
_SUMMARY_BUCKETS = ("ok", "fail", "warn", "unlicensed", "unknown")


class BuildLicenseReport:
    """Build the LICENSE.json artifact from a CycloneDX SBOM.

    The ``process`` method returns the absolute path to the file it writes
    or ``None`` when no report could be generated.
    """

    def __init__(self, output_dir: str = None):
        self.output_dir = output_dir or os.getcwd()

    def process(self, sbom_path, remote_config, pipeline_name):
        policy = build_policy_from_remote_config(remote_config)
        if policy is None:
            logger.error(
                "Cannot build LICENSE report: LICENSE_POLICY missing in remote config."
            )
            return None

        data = self._read_sbom(sbom_path)
        if data is None:
            return None

        dependencies = self._build_dependencies(data, policy)
        report = {
            "metadata": self._build_metadata(
                pipeline_name, remote_config, dependencies
            ),
            "dependencies": dependencies,
        }
        return self._write_report(report, pipeline_name)

    @staticmethod
    def _read_sbom(sbom_path):
        if not sbom_path:
            logger.error("SBOM path is empty; cannot build LICENSE report.")
            return None
        if not os.path.exists(sbom_path):
            logger.error(f"SBOM not found: {sbom_path}")
            return None
        try:
            with open(sbom_path, "r") as fh:
                return json.load(fh)
        except Exception as e:
            logger.error(f"Error reading SBOM '{sbom_path}': {e}")
            return None

    def _build_dependencies(self, data, policy):
        components = data.get("components", [])
        dependencies = []
        for component in components:
            pkg_name = component.get("name", "unknown")
            pkg_version = component.get("version", "")
            raw_licenses = component.get("licenses", [])
            licenses = [
                entry.get("license", entry) for entry in raw_licenses
                if isinstance(entry, dict)
            ]

            classification = classify_package(licenses, policy)
            dependencies.append(
                {
                    "name": pkg_name,
                    "version": pkg_version,
                    "licenses": classification["licenses"],
                    "policy_applied": classification["policy_applied"],
                    "policy_reason": classification["reason"],
                    "policy_pattern_matched": classification[
                        "pattern_matched"
                    ],
                    "license_matched": classification["label"],
                }
            )
        return dependencies

    def _build_metadata(self, pipeline_name, remote_config, dependencies):
        policy_used = copy.deepcopy(
            (remote_config or {}).get("LICENSE", {}).get("LICENSE_POLICY", {})
        )

        summary = {
            "total_dependencies": len(dependencies),
        }
        for bucket in _SUMMARY_BUCKETS:
            summary[bucket] = sum(
                1 for d in dependencies if d["policy_applied"] == bucket
            )

        return {
            "pipeline_name": pipeline_name,
            "scan_date": datetime.now().isoformat(timespec="seconds"),
            "tool": TOOL,
            "policy_used": policy_used,
            "summary": summary,
        }

    def _write_report(self, report, pipeline_name):
        os.makedirs(self.output_dir, exist_ok=True)
        file_name = f"{pipeline_name}_LICENSE.json"
        path = os.path.join(self.output_dir, file_name)
        try:
            with open(path, "w") as fh:
                json.dump(report, fh, indent=2)
            abs_path = os.path.abspath(path)
            logger.info(f"License report saved to: {abs_path}")
            return abs_path
        except Exception as e:
            logger.error(f"Error writing LICENSE report '{path}': {e}")
            return None
