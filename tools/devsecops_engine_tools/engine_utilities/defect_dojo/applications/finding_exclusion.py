from devsecops_engine_tools.engine_utilities.utils.api_error import ApiError
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.user_case.finding_exclusion import FindingExclusionUserCase
from devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.finding_exclusion import FindingExclusionRestConsumer

class FindingExclusion:
    @staticmethod
    def get_finding_exclusion(session, **request):
        try:
            rest_finding_exclusion = FindingExclusionRestConsumer(session=session)

            uc = FindingExclusionUserCase(rest_finding_exclusion)
            return uc.execute(request)
        except ApiError as e:
            raise e