import subprocess
from devsecops_engine_tools.engine_sca.engine_container.src.domain.model.gateways.images_gateway import (
    ImagesGateway,
)
import json


class DockerImages(ImagesGateway):
    def list_images(self):
        """
        Lista las imagenes de Docker en formato json
        """
        command = ["docker", "images", "--format", "json"]
        try:
            results = subprocess.run(
                command,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            results = results.stdout.split("\n")
            results.pop()  
            last_image_json = results[0]  
            last_image_dict = json.loads(last_image_json)
            return [last_image_dict]

        except subprocess.CalledProcessError as e:
            raise ValueError(f"Error listing images:{e.stderr}")
