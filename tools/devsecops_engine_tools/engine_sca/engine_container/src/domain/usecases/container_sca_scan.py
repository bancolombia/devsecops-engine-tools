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
        token,
    ):
        self.tool_run = tool_run
        self.remote_config = remote_config
        self.tool_images = tool_images
        self.tool_deseralizator = tool_deseralizator
        self.build_id = build_id
        self.token = token

    def get_latest_image(self):
        """
        Process the list of images.

        Returns:
            list: List of processed images.
        """
        return self.tool_images.list_images()

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
        latest_image = self.get_latest_image()
        image_name = latest_image.tags[0]
        image_scanned = None
        if (self.build_id) and (self.build_id in image_name):
            result_file = image_name + "_scan_result.json"
            if result_file in self.get_images_already_scanned():
                print(f"The image {image_name} has already been scanned previously.")
                return image_scanned
            image_scanned = self.tool_run.run_tool_container_sca(
                self.remote_config, self.token, image_name, result_file
            )
            self.set_image_scanned(result_file)
        else:
            print(
                f"'{image_name}' name does not contain build number '{self.build_id}'. Tool skipped."
            )
        return image_scanned

    def deseralizator(self, image_scanned):
        """
        Process the results deserializer.

        Returns:
            list: Deserialized list of findings.
        """
        return self.tool_deseralizator.get_list_findings(image_scanned)
