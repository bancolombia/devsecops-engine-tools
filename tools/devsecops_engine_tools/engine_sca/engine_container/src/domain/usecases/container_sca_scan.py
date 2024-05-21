from devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway import (
    DevopsPlatformGateway,
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
        tool_remote: DevopsPlatformGateway,
        tool_images: ImagesGateway,
        tool_deseralizator: DeseralizatorGateway,
        dict_args,
        token
    ):
        self.tool_run = tool_run
        self.tool_remote = tool_remote
        self.tool_images = tool_images
        self.tool_deseralizator = tool_deseralizator
        self.dict_args = dict_args
        self.token = token


    def get_remote_config(self, file_path):
        """
        Get remote configuration.

        Returns:
            dict: Remote configuration.
        """
        return self.tool_remote.get_remote_config(self.dict_args["remote_config_repo"], file_path)

    def scan_image(self):
        """
        Process the list of images.

        Returns:
            list: List of processed images.
        """
        return self.tool_images.list_images()

    def get_variable(self, variable):
        """
        Get variable.

        Returns:
            dict: Remote variable.
        """
        return self.tool_remote.get_variable(variable)

    def process(self):
        """
        Process SCA scanning.

        Returns:
            dict: SCA scanning results.
        """
        return self.tool_run.run_tool_container_sca(
            self.get_remote_config("engine_sca/engine_container/ConfigTool.json"),
            self.token,
            self.scan_image(),
            self.get_variable("build_id")
        )

    def deseralizator(self, image_scanned):
        """
        Process the results deserializer.

        Returns:
            list: Deserialized list of findings.
        """
        return self.tool_deseralizator.get_list_findings(image_scanned)