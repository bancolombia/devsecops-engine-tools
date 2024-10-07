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
        build_id,
        secret_tool,
        token_engine_container,
        image_to_scan,
    ):
        self.tool_run = tool_run
        self.remote_config = remote_config
        self.tool_images = tool_images
        self.tool_deseralizator = tool_deseralizator
        self.build_id = build_id
        self.secret_tool = secret_tool
        self.token_engine_container = token_engine_container
        self.image_to_scan = image_to_scan

    def get_image(self, image_to_scan):
        """
        Process the list of images.

        Returns:
            list: List of processed images.
        """
        return self.tool_images.list_images(image_to_scan)

    def get_images_already_scanned(self):
        """
        Create images scanned file if it does not exist and get the images that have already been scanned.
        """
        scanned_images_file = os.path.join(os.getcwd(), "scanned_images.txt")
        if not os.path.exists(scanned_images_file):
            open(scanned_images_file, "w").close()
        with open(scanned_images_file, "r") as file:
            images_scanned = file.read().splitlines()
        return images_scanned

    def set_image_scanned(self, result_file):
        """
        Write in scanned_images.txt the result file
        """
        with open("scanned_images.txt", "a") as file:
            file.write(result_file + "\n")

    def process(self):
        """
        Process SCA scanning.

        Returns:
            string: file scanning results name.
        """
        matching_image = self.get_image(self.image_to_scan)
        image_scanned = None
        if matching_image:
            image_name = matching_image.tags[0]
            result_file = image_name.replace("/","_") + "_scan_result.json"
            if image_name in self.get_images_already_scanned():
                print(f"The image {image_name} has already been scanned previously.")
                return image_scanned
            image_scanned = self.tool_run.run_tool_container_sca(
                self.remote_config, self.secret_tool, self.token_engine_container, image_name, result_file
            )
            self.set_image_scanned(image_name)
        else:
            print(f"'Not image found for {self.image_to_scan}'. Tool skipped.")
        return image_scanned

    def deseralizator(self, image_scanned):
        """
        Process the results deserializer.

        Returns:
            list: Deserialized list of findings.
        """
        return self.tool_deseralizator.get_list_findings(image_scanned)
