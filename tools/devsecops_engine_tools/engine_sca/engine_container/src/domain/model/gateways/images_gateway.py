from abc import ABCMeta, abstractmethod


class ImagesGateway(metaclass=ABCMeta):
    @abstractmethod
    def list_images(self, image_to_scan) -> str:
        "get image to scan"

    @abstractmethod
    def get_base_image(self, image_to_scan) -> str:
        "get base image"

    @abstractmethod
    def validate_base_image_date(self, image_to_scan, referenced_date) -> str:
        "validate base image date"