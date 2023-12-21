
from abc import ABCMeta, abstractmethod


class ImagesScannedGateway(metaclass=ABCMeta):

    @abstractmethod
    def get_images_already_scanned_file(self):
        "Get the file name of images already been scanned."
    
    @abstractmethod
    def get_images_already_scanned(self, file_name):
        "Get the images that have already been scanned."
    
