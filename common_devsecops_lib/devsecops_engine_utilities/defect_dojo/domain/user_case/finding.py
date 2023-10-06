from devsecops_engine_utilities.defect_dojo.infraestructure.driver_adapters.finding import FindingRestConsumer
from devsecops_engine_utilities.defect_dojo.domain.request_objects.finding import FindingRequest


class FindingUserCase:
    def __init__(self, rest_finding: FindingRestConsumer):
        self.__rest_finding = rest_finding

    def execute(request: FindingRequest):
        print("execute", request)
