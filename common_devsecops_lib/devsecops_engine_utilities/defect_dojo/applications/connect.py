from devsecops_engine_utilities.defect_dojo.\
    domain.request_objects.import_scan import ImportScanRequest
from devsecops_engine_utilities.defect_dojo.\
    domain.serializers.import_scan import ImportScanSerializer
from devsecops_engine_utilities.defect_dojo.\
    domain.user_case.cmdb import CmdbUserCase
from devsecops_engine_utilities.defect_dojo.\
    infraestructure.driver_adapters.cmdb import CmdbRestConsumer
from devsecops_engine_utilities.utils.azure_devops_api import AzureDevopsApi


class Connect:
    @staticmethod
    # Configuration Management Database aws
    def cmdb(**kwargs) -> ImportScanRequest:
        request: ImportScanRequest = ImportScanSerializer().load(kwargs)
        rc = CmdbRestConsumer(request,
                              token=request.token_cmdb,
                              host=request.host_cmdb,
                              mapping_cmdb=request.cmdb_mapping)

        utils_azure = AzureDevopsApi(
            personal_access_token=request.personal_access_token,
            project_remote_config=request.project_remote_config,
            organization_url=request.organization_url)

        uc = CmdbUserCase(rest_consumer_cmdb=rc,
                          utils_azure=utils_azure)

        response = uc.execute(request)
        return response
