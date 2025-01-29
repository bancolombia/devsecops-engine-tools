from devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.finding_exclusion import FindingExclusionRestConsumer

class FindingExclusionUserCase:
    def __init__(self, rest_finding_exclusion: FindingExclusionRestConsumer):
        self.__rest_finding_exclusion = rest_finding_exclusion

    def execute(self, request):
        response = self.__rest_finding_exclusion.get_finding_exclusions(request)
        return response
