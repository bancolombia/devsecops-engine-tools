import re

from devsecops_engine_tools.engine_core.src.domain.model.input_core import InputCore
from devsecops_engine_tools.engine_core.src.domain.model.threshold import Threshold
from devsecops_engine_tools.engine_core.src.domain.model.exclusions import Exclusions
from devsecops_engine_tools.engine_utilities.utils.utils import Utils


class SetInputCore:
    def __init__(self, remote_config, exclusions, pipeline_name, tool):
        self.remote_config = remote_config
        self.exclusions = exclusions
        self.pipeline_name = pipeline_name
        self.tool = tool

    def _build_exclusions(self, items):
        return [
            Exclusions(
                id=item.get("id", ""),
                where=item.get("where", ""),
                cve_id=item.get("cve_id", ""),
                create_date=item.get("create_date", ""),
                expired_date=item.get("expired_date", ""),
                severity=item.get("severity", ""),
                priority=item.get("priority", ""),
                hu=item.get("hu", ""),
                reason=item.get("reason", "DevSecOps policy"),
            )
            for item in items
        ]

    def get_exclusions(self, exclusions_data, pipeline_name, tool):
        list_exclusions = self._get_direct_exclusions(exclusions_data, pipeline_name, tool)

        if pipeline_name not in exclusions_data:
            list_exclusions.extend(self._get_pattern_exclusions(exclusions_data, pipeline_name, tool))

        return list_exclusions

    def _get_direct_exclusions(self, exclusions_data, pipeline_name, tool):
        exclusions = []
        for key, value in exclusions_data.items():
            if key in ("All", pipeline_name) and value.get(tool, 0):
                exclusions.extend(self._build_exclusions(value[tool]))
        return exclusions

    def _get_pattern_exclusions(self, exclusions_data, pipeline_name, tool):
        for pattern, values in exclusions_data.get("BY_PATTERN_SEARCH", {}).items():
            if re.match(pattern, pipeline_name, re.IGNORECASE):
                if values.get(tool, 0):
                    return self._build_exclusions(values[tool])
                break
        return []

    def set_input_core(self, dependencies_scanned):
        """
        Set the input core.

        Returns:
            dict: Input core.
        """
        return InputCore(
            self.get_exclusions(
                self.exclusions,
                self.pipeline_name,
                self.tool,
            ),
            Utils.update_threshold(
                self,
                Threshold(self.remote_config["THRESHOLD"]),
                self.exclusions,
                self.pipeline_name,
            ),
            dependencies_scanned,
            self.remote_config["MESSAGE_INFO_ENGINE_DEPENDENCIES"],
            self.pipeline_name,
            self.pipeline_name,
            "Build",
        )
