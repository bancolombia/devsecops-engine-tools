import re

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

    def _build_exclusions(self, items, base_image_list, filter_by_base_image):
        list_exclusions = []
        for item in items:
            if filter_by_base_image:
                key_image_exception = self.remote_config.get("GET_IMAGE_BASE", {}).get("LABEL_KEYS", {}).get("key_image_exception", None)
                source_images = item.get(key_image_exception, [])
                if source_images and not base_image_list:
                    continue
                if source_images and not any(img in source for img in base_image_list for source in source_images):
                    continue

            list_exclusions.append(
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
            )
        return list_exclusions

    def get_exclusions(self, exclusions_data, pipeline_name, tool, base_image):
        list_exclusions = []
        base_image_list = base_image[0][0] if base_image else None
        print("The base image used is:", base_image_list)
        for key, value in exclusions_data.items():
            if key not in {"All", pipeline_name} or not value.get(tool):
                continue

            list_exclusions.extend(
                self._build_exclusions(value[tool], base_image_list, key == "All")
            )

        if pipeline_name not in exclusions_data:
            for pattern, values in exclusions_data.get(
                "BY_PATTERN_SEARCH", {}
            ).items():
                if re.match(pattern, pipeline_name, re.IGNORECASE):
                    if values.get(tool):
                        list_exclusions.extend(
                            self._build_exclusions(values[tool], base_image_list, False)
                        )
                    break

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
