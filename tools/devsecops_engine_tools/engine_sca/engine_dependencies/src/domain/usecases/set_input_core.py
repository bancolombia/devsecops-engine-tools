from devsecops_engine_tools.engine_core.src.domain.model.input_core import InputCore
from devsecops_engine_tools.engine_core.src.domain.model.threshold import Threshold
from devsecops_engine_tools.engine_core.src.domain.model.exclusions import Exclusions


class SetInputCore:
    def __init__(self, remote_config, exclusions, pipeline_name, tool):
        self.remote_config = remote_config
        self.exclusions = exclusions
        self.pipeline_name = pipeline_name
        self.tool = tool

    def get_exclusions(self, exclusions_data, pipeline_name, tool):
        list_exclusions = []
        for key, value in exclusions_data.items():
            if (key == "All") or (key == pipeline_name):
                if value.get(tool, 0):
                    exclusions = [
                        Exclusions(
                            id=item.get("id", ""),
                            where=item.get("where", ""),
                            cve_id=item.get("cve_id", ""),
                            create_date=item.get("create_date", ""),
                            expired_date=item.get("expired_date", ""),
                            severity=item.get("severity", ""),
                            hu=item.get("hu", ""),
                            reason=item.get("reason", "Risk acceptance"),
                        )
                        for item in value[tool]
                    ]
                    list_exclusions.extend(exclusions)
        return list_exclusions

    def update_threshold(self, threshold, exclusions_data, pipeline_name):
        if (pipeline_name in exclusions_data) and (
            exclusions_data[pipeline_name].get("THRESHOLD", 0)
        ):
            threshold["VULNERABILITY"] = exclusions_data[pipeline_name][
                "THRESHOLD"
            ].get("VULNERABILITY")
        return threshold

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
            Threshold(
                self.update_threshold(
                    self.remote_config["THRESHOLD"], self.exclusions, self.pipeline_name
                )
            ),
            dependencies_scanned,
            self.remote_config["MESSAGE_INFO_ENGINE_DEPENDENCIES"],
            self.pipeline_name,
            "Build",
        )
