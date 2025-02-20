from datetime import datetime
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

    def validate_base_image_date(self, matching_image, referenced_date):
        client = docker.from_env()
        image_details = client.api.inspect_image(matching_image.id)
        labels = image_details.get("Config", {}).get("Labels", {})
        baseline_date = labels.get("x86.baseline.date")
        if baseline_date is None:
            base_image = self.get_base_image_from_labels(labels)
            date_image = self.extract_date_from_image(base_image)
            return self.validate_date(date_image, referenced_date)
        else:
            return self.validate_date(datetime.strptime(baseline_date, "%Y%m%d"), referenced_date)
                
    def get_base_image_from_labels(self, labels):
        if labels.get("image.base.digest"):
            return labels.get("image.base.ref.name")
        else:
            return labels.get("source_images") or labels.get("source-image")
        
    def extract_date_from_image(self, image_name):
        date = image_name.split("_")[-1]
        try:
            return datetime.strptime(date, "%Y%m%d")
        except ValueError:
            return None
    
    def validate_date(self, date, referenced_date):
        reference_date = datetime.strptime(referenced_date, "%Y%m%d")
        if date < reference_date:
            raise ValueError(f"The source base image date ({date.strftime('%Y-%m-%d')}) is older than the referenced date ({reference_date.strftime('%Y-%m-%d')}).")
        else:
            return True
