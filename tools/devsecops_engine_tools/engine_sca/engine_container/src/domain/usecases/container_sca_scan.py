from devsecops_engine_tools.engine_sca.engine_container.src.domain.model.gateways.tool_gateway import (
    ToolGateway,
)
from devsecops_engine_tools.engine_sca.engine_container.src.domain.model.gateways.images_gateway import (
    ImagesGateway,
)
from devsecops_engine_tools.engine_sca.engine_container.src.domain.model.gateways.deserealizator_gateway import (
    DeseralizatorGateway,
)


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

    def scan_image(self):
        """
        Process the list of images.

        Returns:
            list: List of processed images.
        """
        return self.tool_images.list_images()

    def process(self):
        """
        Process SCA scanning.

        Returns:
            dict: SCA scanning results.
        """
        return self.tool_run.run_tool_container_sca(
            self.remote_config, self.token, self.scan_image(), self.build_id
        )

    def deseralizator(self, image_scanned):
        """
        Process the results deserializer.

        Returns:
            list: Deserialized list of findings.
        """
        return self.tool_deseralizator.get_list_findings(image_scanned)
