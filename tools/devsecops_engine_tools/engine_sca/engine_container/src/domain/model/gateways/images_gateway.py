from abc import ABCMeta, abstractmethod


class ImagesGateway(metaclass=ABCMeta):
    @abstractmethod
    def list_images(self, image_to_scan) -> str:
        "get image to scan"
