import subprocess
from devsecops_engine_tools.engine_sca.engine_container.src.domain.model.gateways.images_gateway import (
    ImagesGateway,
)
import docker

from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()

class DockerImages(ImagesGateway):
    def list_images(self):
        try:
            client = docker.from_env()
            images = client.images.list()
            images_sorted = sorted(
                images, key=lambda x: x.attrs["Created"], reverse=True
            )
            latest_image = images_sorted[0]
            print("ID last image:", latest_image.id)
            print("Tag last image:", latest_image.tags)
            print("Created date last image:", latest_image.attrs["Created"])
            return latest_image
        except Exception as e:
            logger.error(f"Error listing images, docker must be running and added to PATH: {e}")
