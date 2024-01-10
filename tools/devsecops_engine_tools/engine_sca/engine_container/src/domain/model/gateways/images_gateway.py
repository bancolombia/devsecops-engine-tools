from abc import ABCMeta, abstractmethod


class ImagesGateway(metaclass=ABCMeta):
    @abstractmethod
    def list_images(self) -> str:
        "list images docker"
