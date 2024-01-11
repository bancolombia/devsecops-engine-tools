from devsecops_engine_tools.engine_sca.engine_container.src.domain.model.gateways.config_gateway import (
    ConfigGateway,
)
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
        tool_remote: ConfigGateway,
        tool_images: ImagesGateway,
        tool_deseralizator: DeseralizatorGateway,
        dict_args,
        token,
    ):
        self.tool_run = tool_run
        self.tool_remote = tool_remote
        self.tool_images = tool_images
        self.tool_deseralizator = tool_deseralizator
        self.dict_args = dict_args
        self.token = token

    def get_remote_config(self):
        """
        Get remote configuration.

        Returns:
            dict: Remote configuration.
        """
        return self.tool_remote.get_remote_config(self.dict_args)

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
            self.get_remote_config(), self.token, self.scan_image()
        )

    def deseralizator(self, image_scanned):
        """
        Process the results deserializer.

        Returns:
            list: Deserialized list of findings.
        """
        return self.tool_deseralizator.get_list_findings(image_scanned)
