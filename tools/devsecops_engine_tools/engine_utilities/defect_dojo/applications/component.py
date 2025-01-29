from devsecops_engine_tools.engine_utilities.utils.api_error import ApiError
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.component import ComponentRestConsumer
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.user_case.component import ComponentUserCase
from devsecops_engine_tools.engine_utilities.settings import SETTING_LOGGER

logger = MyLogger.__call__(**SETTING_LOGGER).get_logger()

class Component:

    @staticmethod
    def get_component(session, request: dict):
        try:
            rest_component = ComponentRestConsumer(session=session)
            uc = ComponentUserCase(rest_component)
            return uc.get(request)
        except ApiError as e:
            logger.error(f"Error during get component: {e}")
            raise e
    
    @staticmethod
    def create_component(session, request):
        try:
            rest_component = ComponentRestConsumer(session=session)
            uc = ComponentUserCase(rest_component)
            return uc.post(request)
        except ApiError as e:
            raise e
