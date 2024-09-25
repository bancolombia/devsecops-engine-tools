from devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.engagement import EngagementRestConsumer

class EngagementUserCase:
    def __init__(self, rest_engagement: EngagementRestConsumer):
        self.__rest_engagement = rest_engagement

    def execute(self, request):
        response = self.__rest_engagement.get_engagements_by_request(request)
        return response
