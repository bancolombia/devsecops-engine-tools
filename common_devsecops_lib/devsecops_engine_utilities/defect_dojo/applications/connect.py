from devsecops_engine_utilities.settings import (PERSONAL_ACCESS_TOKEN,
                                                 REMOTE_CONFIG_PATH,
                                                 REMOTE_CONFIG_REPO,
                                                 SYSTEM_TEAM_PROJECT_ID,
                                                 ORGANIZATION_URL)
from devsecops_engine_utilities.defect_dojo.domain.request_objects.import_scan import ImportScanRequest
from devsecops_engine_utilities.defect_dojo.domain.serializers.import_scan import ImportScanSerializer
from devsecops_engine_utilities.defect_dojo.domain.user_case.cmdb import CmdbUserCase
from devsecops_engine_utilities.defect_dojo.infraestructure.driver_adapters.cmdb import CmdbRestConsumer
from devsecops_engine_utilities.defect_dojo.infraestructure.repository.settings import SettingRepo


class Connect:
    @staticmethod
    # Configuration Management Database aws
    def cmdb(**kwargs) -> ImportScanRequest:
        request: ImportScanRequest = ImportScanSerializer().load(kwargs)
        rc = CmdbRestConsumer(request, token=request.token, host=request.host)
        repo_settings = SettingRepo(
            personal_access_token=PERSONAL_ACCESS_TOKEN,
            remote_config_path=REMOTE_CONFIG_PATH,
            remote_config_repo=REMOTE_CONFIG_REPO,
            system_team_project_id=SYSTEM_TEAM_PROJECT_ID,
            organization_url=ORGANIZATION_URL)
        uc = CmdbUserCase(rest_consumer_cmdb=rc, settings=repo_settings)
        response = uc.execute(request)
        return response
