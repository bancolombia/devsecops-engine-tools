from devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.component import ComponentRestConsumer

class ComponentUserCase:
    def __init__(self, rest_component: ComponentRestConsumer):
        self.__rest_component = rest_component

    def get(self, request):
        return self.__rest_component.get_component(request)
    
    def post(self, request):
        return self.__rest_component.post_component(request)
