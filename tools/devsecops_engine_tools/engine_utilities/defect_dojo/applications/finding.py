from devsecops_engine_tools.engine_utilities.defect_dojo.domain.request_objects.finding import FindingRequest
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.serializers.finding import FindingSerializer
from devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.finding import FindingRestConsumer
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.user_case.finding import FindingUserCase, FindingGetUserCase
from devsecops_engine_tools.engine_utilities.utils.session_manager import SessionManager
from devsecops_engine_tools.engine_utilities.utils.api_error import ApiError
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


class Finding:
    @staticmethod
    def serializer(*args, **request):
        serializer = FindingSerializer()
        errors = serializer.validate(request)
        if errors:
            logger.error(errors)
            raise Exception(errors)

    @staticmethod
    def close_finding(session, **request):
        try:
            Finding.serializer(**request)
            rest_finding = FindingRestConsumer(session=session)
            uc = FindingUserCase(rest_finding)
            return uc.execute(request)
        except Exception as e:
            raise e

    @staticmethod
    def get_finding(session, **request):
        try:
            Finding.serializer(**request)
            rest_finding = FindingRestConsumer(session=session)
            uc = FindingGetUserCase(rest_finding)
            return uc.execute(request)
        except Exception as e:
            raise e
