from devsecops_engine_tools.engine_core.src.domain.model.input_core import InputCore
from devsecops_engine_tools.engine_core.src.domain.model.exclusions import Exclusions
from devsecops_engine_tools.engine_core.src.domain.model.threshold import Threshold
from devsecops_engine_tools.engine_utilities.utils.utils import Utils


class SetInputCore:
    def __init__(self, remote_config, exclusions, pipeline_name, tool, stage):
        self.remote_config = remote_config
        self.exclusions = exclusions
        self.pipeline_name = pipeline_name
        self.tool = tool
        self.stage = stage

    def get_exclusions(self, exclusions_data, pipeline_name, tool, base_image):
        list_exclusions = []
        print("The base image used is:", base_image)
        for key, value in exclusions_data.items():
            if key not in {"All", pipeline_name} or not value.get(tool):
                continue

            for item in value[tool]:
                if key == "All":
                    source_images = item.get("x86.image.name", [])
                    if source_images and base_image is None:
                        continue
                    if source_images and not any(base_image in source for source in source_images):
                        continue
                    
                list_exclusions.append(
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
                )

        return list_exclusions

    def set_input_core(self, image_scanned,base_image):
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
                base_image
            ),
            Utils.update_threshold(
                self,
                Threshold(self.remote_config["THRESHOLD"]),
                self.exclusions,
                self.pipeline_name,
            ),
            image_scanned,
            self.remote_config["MESSAGE_INFO_ENGINE_CONTAINER"],
            self.pipeline_name,
            self.pipeline_name,
            self.stage.capitalize(),
        )
