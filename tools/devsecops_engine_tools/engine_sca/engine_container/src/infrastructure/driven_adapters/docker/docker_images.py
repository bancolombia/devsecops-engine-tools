from devsecops_engine_tools.engine_sca.engine_container.src.domain.model.gateways.images_gateway import (
    ImagesGateway,
)
import docker

from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


class DockerImages(ImagesGateway):
    def list_images(self, image_to_scan):
        try:
            client = docker.from_env()
            images = client.images.list()

            matching_image = None
            for image in images:
                if any(image_to_scan in tag for tag in image.tags):
                    matching_image = image
                    break

            if matching_image:
                print("ID matching image:", matching_image.id)
                print("Tag matching image:", matching_image.tags)
                print("Created date matching image:", matching_image.attrs["Created"])
                return matching_image

        except Exception as e:
            logger.error(
                f"Error listing images, docker must be running and added to PATH: {e}"
            )

    def get_base_image(self, matching_image):
        try:
            client = docker.from_env()
            image_details = client.api.inspect_image(matching_image.id)
            labels = image_details.get("Config", {}).get("Labels", {})
            source_image = labels.get("x86.image.name")
            if source_image:
                logger.info(f"Base image for '{matching_image}' from source-image label: {source_image}")
                return source_image

            logger.warning(f"Base image not found for '{matching_image}'.")
            return None

        except Exception as e:
            logger.error(f"Error getting base image: {e}")
            return None