from devsecops_engine_tools.engine_utilities.utils.api_error import ApiError
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.user_case.product import ProductUserCase
from devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.product import ProductRestConsumer

class Product:
    @staticmethod
    def get_product(session, request: dict):
        try:
            rest_product = ProductRestConsumer(session=session)

            uc = ProductUserCase(rest_product)
            return uc.execute(request)
        except ApiError as e:
            raise e