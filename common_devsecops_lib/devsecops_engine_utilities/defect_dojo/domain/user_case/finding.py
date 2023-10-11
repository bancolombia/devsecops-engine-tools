from devsecops_engine_utilities.defect_dojo.infraestructure.driver_adapters.finding import FindingRestConsumer
from devsecops_engine_utilities.defect_dojo.domain.serializers.finding import FindingCloseSerializer
from devsecops_engine_utilities.utils.api_error import ApiError
from devsecops_engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_utilities.settings import SETTING_LOGGER
import datetime
import pytz

logger = MyLogger.__call__(**SETTING_LOGGER)


class FindingUserCase:
    def __init__(self, rest_finding: FindingRestConsumer):
        self.__rest_finding = rest_finding

    def execute(self, request):
        findings = self.__rest_finding.get(request)
        if findings.results == []:
            raise ApiError(f"Finding con Id {request.get('unique_id_from_tool')} not found")
        tz = pytz.timezone("America/Bogota")
        date = datetime.datetime.now(tz=tz).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        request_close = {"is_mitigated": "True", "mitigated": date}
        return self.__rest_finding.close(request_close, findings.results[0].id)
