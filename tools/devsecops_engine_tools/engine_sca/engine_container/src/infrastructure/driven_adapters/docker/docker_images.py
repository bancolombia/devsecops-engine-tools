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
            json_list = [json.loads(result) for result in results]
            return json_list

        except subprocess.CalledProcessError as e:
            raise ValueError(f"Error al listar imagenes: {e.stderr}")
