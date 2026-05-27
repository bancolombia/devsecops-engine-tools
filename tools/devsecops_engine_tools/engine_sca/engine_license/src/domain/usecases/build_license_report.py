"""Use case that builds the LICENSE.json artifact from a Grant scan report.

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
import re
from datetime import datetime

from devsecops_engine_tools.engine_sca.engine_license.src.domain.usecases.license_policy import (
    build_policy_from_remote_config,
    classify_package,
    get_value,
)
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()

TOOL = "GRANT"
_SUMMARY_BUCKETS = ("ok", "fail", "warn", "unlicensed", "unknown")


class BuildLicenseReport:
    """Build the LICENSE.json artifact from a Grant scan report.

    The ``process`` method returns the absolute path to the file it writes
    or ``None`` when no report could be generated (e.g. invalid input
    file, missing policy).
    """

    def __init__(self, output_dir: str = None):
        self.output_dir = output_dir or os.getcwd()

    def process(self, grant_report_path, remote_config, pipeline_name):
        policy = build_policy_from_remote_config(remote_config)
        if policy is None:
            logger.error(
                "Cannot build LICENSE report: GRANT.LICENSE_POLICY missing."
            )
            return None

        data = self._read_grant_report(grant_report_path)
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
    def _read_grant_report(grant_report_path):
        if not grant_report_path:
            logger.error("Grant report path is empty; cannot build LICENSE report.")
            return None
        if not os.path.exists(grant_report_path):
            logger.error(f"Grant report not found: {grant_report_path}")
            return None
        try:
            with open(grant_report_path, "r") as fh:
                return json.load(fh)
        except Exception as e:
            logger.error(f"Error reading Grant report '{grant_report_path}': {e}")
            return None

    def _build_dependencies(self, data, policy):
        targets = self._extract_targets(data)
        dependencies = []
        for target in targets:
            source = get_value(target, "source", "Source", default={})
            source_ref = get_value(source, "ref", "Ref", default="")
            source_root = self._source_root_name(source_ref)

            evaluation = get_value(
                target, "evaluation", "Evaluation", default={}
            )
            findings_block = get_value(
                evaluation, "findings", "Findings", default={}
            )
            packages = (
                get_value(findings_block, "packages", "Packages", default=[])
                or []
            )

            for pkg in packages:
                pkg_name = get_value(pkg, "name", "Name", default="unknown")
                pkg_version = get_value(pkg, "version", "Version", default="")
                licenses = (
                    get_value(pkg, "licenses", "Licenses", default=[]) or []
                )

                if source_root and self._is_root_project(pkg_name, source_root):
                    continue

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
                    }
                )
        return dependencies

    @staticmethod
    def _extract_targets(data):
        run = get_value(data, "run", "Run", default={})
        targets = get_value(run, "targets", "Targets")
        if targets:
            return targets
        return data.get("results") or data.get("Results") or []

    @staticmethod
    def _source_root_name(source_ref):
        if not source_ref:
            return ""
        base = os.path.basename(source_ref)
        base = re.sub(r"\.(cdx|spdx)?\.?(json|xml|yaml|yml)$", "", base, flags=re.I)
        base = re.sub(r"[_\-]sbom$", "", base, flags=re.I)
        return base.strip().lower()

    @staticmethod
    def _is_root_project(pkg_name, source_root_name):
        if not pkg_name or not source_root_name:
            return False
        return pkg_name.strip().lower() == source_root_name

    def _build_metadata(self, pipeline_name, remote_config, dependencies):
        policy_used = copy.deepcopy(
            (remote_config or {}).get(TOOL, {}).get("LICENSE_POLICY", {})
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
