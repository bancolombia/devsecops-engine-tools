from devsecops_engine_tools.engine_sca.engine_container.src.domain.model.gateways.tool_gateway import ToolGateway
from devsecops_engine_tools.engine_sca.engine_container.src.domain.model.gateways.images_gateway import ImagesGateway
from devsecops_engine_tools.engine_sca.engine_container.src.domain.model.gateways.deserealizator_gateway import DeseralizatorGateway


class ContainerScaScan():

    def __init__(self, tool_run: ToolGateway,tool_images: ImagesGateway,tool_deseralizator:DeseralizatorGateway, dict_args, token):
        self.tool_run = tool_run
        self.tool_images = tool_images
        self.tool_deseralizator = tool_deseralizator
        self.dict_args  = dict_args
        self.token = token
    
    def scanImage(self):    
        """
        Procesa el listado de imagenes.
        """
        return self.tool_images.list_images_docker()

    
    def process(self):
        """
        Procesa el escaneo de SCA.
        """
        return self.tool_run.run_tool_container_sca(self.dict_args, self.token,self.scanImage())
    
    def deseralizator(self):
        """
        Procesa el deseralizador de resultados.
        """
        return self.tool_deseralizator.get_list_vulnerability(self.process())
