from devsecops_engine_tools.engine_utilities.utils.api_error import ApiError
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.request_objects.import_scan import ImportScanRequest
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.settings.settings import VERIFY_CERTIFICATE
from devsecops_engine_tools.engine_utilities.utils.session_manager import SessionManager
from devsecops_engine_tools.engine_utilities.settings import SETTING_LOGGER

logger = MyLogger.__call__(**SETTING_LOGGER).get_logger()


class ReimportScanRestConsumer:

    def __init__(self, request: ImportScanRequest, session: SessionManager):
        self.__token = request.token_defect_dojo
        self.__host = request.host_defect_dojo
        self.__session = session._instance

    def reimport_scan(self, request: ImportScanRequest, files) -> ImportScanRequest:
        url = f"{self.__host}/api/v2/reimport-scan/"
        logger.debug(f"URL: {url}")
        payload = {
            "scan_date": request.scan_date,
            "minimum_severity": request.minimum_severity,
            "active": request.active,
            "verified": request.verified,
            "scan_type": request.scan_type,
            "endpoint_to_add": request.endpoint_to_add,
            "file": files,
            "product_type_name": request.product_type_name,
            "product_name": request.product_name,
            "engagement_name": request.engagement_name,
            "engagement_end_date": request.engagement_end_date,
            "source_code_management_uri": request.source_code_management_uri,
            "auto_create_context": "true",
            "deduplication_on_engagement": request.deduplication_on_engagement,
            "lead": request.lead,
            "push_to_jira": request.push_to_jira,
            "environment": request.environment,
            "build_id": request.build_id,
            "branch_tag": request.branch_tag,
            "commit_hash": request.commit_hash,
            "api_scan_configuration": str(request.api_scan_configuration)
            if request.api_scan_configuration != 0
            else "",
            "service": request.service,
            "group_by": request.group_by,
            "create_finding_groups_for_all_findings": request.create_finding_groups_for_all_findings,
            "do_not_reactive"
            "scan_type": request.scan_type,
            "close_old_findings": request.close_old_findings,
            "close_old_findings_product_scope": request.close_old_findings_product_scope,
            "version": request.version,
            "tags": request.tags,
            "test_title": request.test_title,
        }

        headers = {"Authorization": f"Token {self.__token}"}
        try:
            response = self.__session.post(
                url,
                headers=headers,
                data=payload,
                files=files,
                verify=VERIFY_CERTIFICATE
            )
            if response.status_code != 201:
                logger.error(response.json())
                raise ApiError(response.json())
            logger.info(f"Sucessfull {response}")
            response = ImportScanRequest.from_dict(response.json())
        except Exception as e:
            logger.error(f"from dict import Scan: {response.json()}")
            raise ApiError(e)
        return response
