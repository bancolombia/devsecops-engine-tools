import subprocess
from devsecops_engine_tools.engine_sca.engine_container.src.domain.model.gateways.images_gateway import (
    ImagesGateway,
)
import json

import docker



class DockerImages(ImagesGateway):
    def list_images(self):
        try:   
            client = docker.from_env()

            images = client.images.list()

            # Ordenamos las imágenes por fecha de creación en orden descendente
            images_sorted = sorted(images, key=lambda x: x.attrs['Created'], reverse=True)

            latest_image = images_sorted[0]
            
            print("ID de la última imagen:", latest_image.id)
            print("Tag de la última imagen:", latest_image.tags)
            print("Fecha de creación de la última imagen:", latest_image.attrs['Created'])
            
            return latest_image
        except subprocess.CalledProcessError as e:
                raise ValueError(f"Error listing images:{e.stderr}")