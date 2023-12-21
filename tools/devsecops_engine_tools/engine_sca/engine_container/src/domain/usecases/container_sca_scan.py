from devsecops_engine_tools.engine_sca.engine_container.src.domain.model.gateways.tool_gateway import ToolGateway
from devsecops_engine_tools.engine_sca.engine_container.src.domain.model.gateways.images_gateway import ImagesGateway
from devsecops_engine_tools.engine_sca.engine_container.src.domain.model.gateways.deserealizator_gateway import DeseralizatorGateway
from devsecops_engine_tools.engine_sca.engine_container.src.domain.model.gateways.images_scanned_gateway import ImagesScannedGateway


class ContainerScaScan():

    def __init__(self, tool_run: ToolGateway,tool_images: ImagesGateway,tool_deseralizator:DeseralizatorGateway,tool_images_scanned:ImagesScannedGateway,dict_args, token):
        self.tool_run = tool_run
        self.tool_images = tool_images
        self.tool_deseralizator = tool_deseralizator
        self.tool_images_scanned = tool_images_scanned
        self.dict_args  = dict_args
        self.token = token
    
    def scanImage(self):    
        """
        Procesa el listado de imagenes.
        """
        return self.tool_images.list_images_docker()

    def getfilename(self):
        """
        Get the file name of images already been scanned.
        """
        return self.tool_images_scanned.get_images_already_scanned_file()
    
    def getscannedimages(self):
        """
        Get the images that have already been scanned.
        """
        return self.tool_images_scanned.get_images_already_scanned(self.getfilename())
    
    def process(self):
        """
        Procesa el escaneo de SCA.
        """
        return self.tool_run.run_tool_container_sca(self.dict_args,self.token,self.scanImage(),self.getfilename(),self.getscannedimages())
    
    def deseralizator(self):
        """
        Procesa el deseralizador de resultados.
        """
        return self.tool_deseralizator.get_list_vulnerability(self.process())

