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
                            reason=item.get("reason", "DevSecOps policy"),
                        )
                        for item in value[tool]
                    ]
                    list_exclusions.extend(exclusions)
        return list_exclusions

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
