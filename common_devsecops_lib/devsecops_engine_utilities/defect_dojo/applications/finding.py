from devsecops_engine_utilities.defect_dojo.domain.request_objects.finding import FindingRequest
from devsecops_engine_utilities.defect_dojo.domain.serializers.finding import FindingSerializer
from devsecops_engine_utilities.defect_dojo.infraestructure.driver_adapters.finding import FindingRestConsumer
from devsecops_engine_utilities.defect_dojo.domain.user_case.finding import FindingUserCase
from devsecops_engine_utilities.utils.session_manager import SessionManager
from devsecops_engine_utilities.utils.api_error import ApiError
from devsecops_engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


class Finding:
    @staticmethod
    def close_finding(session, **request):
        try:
            serializer = FindingSerializer()
            errors = serializer.validate(request)
            logger.debug(f"Validation OK")
            if errors:
                logger(f"search error {errors}")
                return errors
            rest_finding = FindingRestConsumer(session=session)
            uc = FindingUserCase(rest_finding)
            return uc.execute(request)
        except Exception as e:
            raise ApiError(e)
