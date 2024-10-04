from devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.product import ProductRestConsumer

class ProductUserCase:
    def __init__(self, rest_product: ProductRestConsumer):
        self.__rest_product = rest_product

    def execute(self, request):
        response = self.__rest_product.get_products(request)
        return response
