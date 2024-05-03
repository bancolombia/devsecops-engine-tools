from devsecops_engine_tools.engine_utilities.utils.api_error import ApiError
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.request_objects.import_scan import ImportScanRequest
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.serializers.import_scan import ImportScanSerializer
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.user_case.cmdb import CmdbUserCase
from devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.cmdb import CmdbRestConsumer
from devsecops_engine_tools.engine_utilities.azuredevops.infrastructure.azure_devops_api import AzureDevopsApi
from devsecops_engine_tools.engine_utilities.utils.session_manager import SessionManager


class Connect:
    @staticmethod
    # Configuration Management Database aws
    def cmdb(**kwargs) -> ImportScanRequest:
        try:
            request: ImportScanRequest = ImportScanSerializer().load(kwargs)
            rc = CmdbRestConsumer(
                token=request.token_cmdb,
                host=request.host_cmdb,
                mapping_cmdb=request.cmdb_mapping,
                session=SessionManager(),
            )

            utils_azure = AzureDevopsApi(
                personal_access_token=request.personal_access_token,
                project_remote_config=request.project_remote_config,
                organization_url=request.organization_url,
                compact_remote_config_url=request.compact_remote_config_url,
                repository_id=request.repository_id,
                remote_config_path=request.remote_config_path,
            )

            uc = CmdbUserCase(rest_consumer_cmdb=rc, utils_azure=utils_azure, expression=request.expression)
            response = uc.execute(request)
        except Exception as e:
            return e

        return response
