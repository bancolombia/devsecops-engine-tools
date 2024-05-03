from devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.finding import FindingRestConsumer
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.serializers.finding import FindingCloseSerializer
from devsecops_engine_tools.engine_utilities.utils.api_error import ApiError
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities.settings import SETTING_LOGGER
import datetime
import pytz

logger = MyLogger.__call__(**SETTING_LOGGER).get_logger()


class FindingUserCase:
    def __init__(self, rest_finding: FindingRestConsumer):
        self.__rest_finding = rest_finding

    def execute(self, request):
        findings = self.__rest_finding.get(request)
        if findings.results == []:
            logger.error("Finding con Id_from_tool {request.get('unique_id_from_tool')} not found")
            raise ApiError(f"Finding con Id_from_tool {request.get('unique_id_from_tool')} not found")
        tz = pytz.timezone("America/Bogota")
        date = datetime.datetime.now(tz=tz).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        logger.debug(f"date: {date}")
        response = None
        for finding in findings.results:
            request_close = {"is_mitigated": "True", "mitigated": date}
            response = self.__rest_finding.close(request_close, finding.id)
        return response


class FindingGetUserCase:
    def __init__(self, rest_finding: FindingRestConsumer):
        self.__rest_finding = rest_finding

    def execute(self, request):
        response = self.__rest_finding.get(request)
        logger.debug(f"finding: {response}")
        return response
