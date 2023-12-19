
from abc import ABCMeta, abstractmethod


class ImagesGateway(metaclass=ABCMeta):

    @abstractmethod
    def list_images_docker  (self) -> str:
        "list images docker"
    
