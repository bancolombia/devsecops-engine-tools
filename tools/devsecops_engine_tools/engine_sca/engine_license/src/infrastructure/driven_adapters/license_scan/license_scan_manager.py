import json
from typing import List

from devsecops_engine_tools.engine_sca.engine_license.src.domain.model.context_license import (
    ContextLicense,
)

_RELEVANT_POLICIES = ("fail", "warn")


class LicenseScanManager:
    """Reads the LICENSE.json and provides context extraction for engine_license."""

    def get_license_context_from_results(self, path_file_results) -> List[ContextLicense]:
        with open(path_file_results, "r") as fh:
            data = json.load(fh)

        context_list = []
        for dep in data.get("dependencies", []):
            policy = dep.get("policy_applied", "unknown")
            if policy not in _RELEVANT_POLICIES:
                continue
            context_list.append(
                ContextLicense(
                    name=dep.get("name", "unknown"),
                    version=dep.get("version", ""),
                    licenses=dep.get("licenses", []),
                    policy_applied=policy,
                    policy_reason=dep.get("policy_reason", ""),
                    policy_pattern_matched=dep.get("policy_pattern_matched", "") or "",
                    severity=dep.get("severity", "info"),
                )
            )
        return context_list
