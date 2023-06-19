from defect_dojo.domain.request_objects.import_scan\
    import ImportScanRequest
from defect_dojo.domain.serializers.import_scan\
    import ImportScanSerializer
from defect_dojo.domain.user_case.cmdb\
     import CmdbUserCase
from defect_dojo.infraestructure.driver_adapters.cmdb\
    import CmdbRestConsumer


class Connect:

    @staticmethod
    # Configuration Management Database aws
    def cmdb(**kwargs) -> ImportScanRequest:
        request: ImportScanRequest = ImportScanSerializer().load(kwargs)
        rc = CmdbRestConsumer(request,
                              token=request.token,
                              host=request.host)
        uc = CmdbUserCase(rest_consumer_cmdb=rc)
        response = uc.execute(request)
        return response

