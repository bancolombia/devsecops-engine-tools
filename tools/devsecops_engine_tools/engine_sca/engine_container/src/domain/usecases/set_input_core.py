from devsecops_engine_tools.engine_core.src.domain.model.input_core import InputCore
from devsecops_engine_tools.engine_core.src.domain.model.threshold import Threshold


from devsecops_engine_tools.engine_core.src.domain.model.exclusions import Exclusions


class SetInputCore:
    def __init__(self, remote_config, exclusions, pipeline_name, tool, stage):
        self.remote_config = remote_config
        self.exclusions = exclusions
        self.pipeline_name = pipeline_name
        self.tool = tool
        self.stage = stage

    def get_exclusions(self, exclusions_data, pipeline_name, tool):
        list_exclusions = [
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
            for key, value in exclusions_data.items()
            if key in {"All", pipeline_name} and value.get(tool)
            for item in value[tool]
        ]
        return list_exclusions

    def set_input_core(self, image_scanned):
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
            Threshold(self.remote_config["THRESHOLD"]),
            image_scanned,
            self.remote_config["MESSAGE_INFO_ENGINE_CONTAINER"],
            self.pipeline_name,
            self.stage.capitalize(),
        )
