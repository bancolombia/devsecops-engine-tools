from devsecops_engine_tools.engine_sca.engine_container.src.domain.model.gateways.tool_gateway import (
    ToolGateway,
)
from devsecops_engine_tools.engine_sca.engine_container.src.domain.model.gateways.images_gateway import (
    ImagesGateway,
)
from devsecops_engine_tools.engine_sca.engine_container.src.domain.model.gateways.deserealizator_gateway import (
    DeseralizatorGateway,
)

import os


class ContainerScaScan:
    def __init__(
        self,
        tool_run: ToolGateway,
        remote_config,
        tool_images: ImagesGateway,
        tool_deseralizator: DeseralizatorGateway,
        branch,
        secret_tool,
        token_engine_container,
        image_to_scan,
        exclusions,
        pipeline_name,
        context,
    ):
        self.tool_run = tool_run
        self.remote_config = remote_config
        self.tool_images = tool_images
        self.tool_deseralizator = tool_deseralizator
        self.branch = branch
        self.secret_tool = secret_tool
        self.token_engine_container = token_engine_container
        self.image_to_scan = image_to_scan
        self.exclusions = exclusions
        self.pipeline_name = pipeline_name
        self.context = context

    def process(self):
        """
        Process SCA scanning.

        Returns:
            string: file scanning results name.
        """
        base_image = None
        image_scanned = None
        matching_image = self._get_image(self.image_to_scan)
        if self.remote_config["GET_IMAGE_BASE"]:
            base_image = self._get_base_image(matching_image)
        if self.remote_config["VALIDATE_BASE_IMAGE_DATE"][
            "ENABLED"
        ] and not self.exclusions.get(self.pipeline_name, {}).get(
            "VALIDATE_BASE_IMAGE_DATE"
        ):
            self._validate_base_image_date(
                matching_image,
                self.remote_config["VALIDATE_BASE_IMAGE_DATE"]["REFERENCE_IMAGE_DATE"],
            )
        if self.remote_config["BLACK_LIST_BASE_IMAGE"][
            "ENABLED"
        ] and not self.exclusions.get(self.pipeline_name, {}).get(
            "BLACK_LIST_BASE_IMAGE"
        ):
            self._validate_black_list_base_image(
                base_image, self.remote_config["BLACK_LIST_BASE_IMAGE"]["BLACK_LIST"]
            )

        sbom_components = None
        generate_sbom = self.remote_config["SBOM"]["ENABLED"] and any(
            branch in str(self.branch)
            for branch in self.remote_config["SBOM"]["BRANCH_FILTER"]
        )
        if matching_image:
            image_name = matching_image.tags[0]
            result_file = image_name.replace("/", "_") + "_scan_result.json"
            image_scanned, sbom_components = self.tool_run.run_tool_container_sca(
                self.remote_config,
                self.secret_tool,
                self.token_engine_container,
                image_name,
                result_file,
                base_image,
                self.exclusions,
                generate_sbom,
            )
        else:
            print(f"'Not image found for {self.image_to_scan}'. Tool skipped.")
        return image_scanned, base_image, sbom_components

    def deseralizator(self, image_scanned):
        """
        Process the results deserializer.

        Returns:
            list: Deserialized list of findings.
        """
        context_flag = self.context
        if context_flag == "true":
            self.tool_deseralizator.get_container_context_from_results(image_scanned)

        return self.tool_deseralizator.get_list_findings(image_scanned)

    def _get_image(self, image_to_scan):
        """
        Process the list of images.

        Returns:
            list: List of processed images.
        """
        return self.tool_images.list_images(image_to_scan)

    def _get_base_image(self, matching_image):
        """
        Process the base image.

        Returns:
            String: base image.
        """
        return self.tool_images.get_base_image(matching_image)

    def _validate_base_image_date(self, matching_image, referenced_date):
        """
        Process the base image date validation.

        Returns:
            string: base image date.
        """
        return self.tool_images.validate_base_image_date(
            matching_image, referenced_date
        )

    def _validate_black_list_base_image(self, base_image, black_list):
        """
        Process the black list image base validation.

        Returns:
            string: blacklist.
        """
        return self.tool_images.validate_black_list_base_image(base_image, black_list)
