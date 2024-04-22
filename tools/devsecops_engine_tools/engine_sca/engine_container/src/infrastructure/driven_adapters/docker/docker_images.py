import subprocess
from devsecops_engine_tools.engine_sca.engine_container.src.domain.model.gateways.images_gateway import (
    ImagesGateway,
)
import docker


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
        except subprocess.CalledProcessError as e:
            raise ValueError(f"Error listing images:{e.stderr}")