from requests_toolbelt.multipart.encoder import MultipartEncoder
from devsecops_engine_utilities.defect_dojo.domain.request_objects.import_scan import ImportScanRequest
from devsecops_engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_utilities.utils.validation_error import ValidationError
from devsecops_engine_utilities.defect_dojo.infraestructure.driver_adapters.settings.settings import VERIFY_CERTIFICATE
from devsecops_engine_utilities.utils.session_manager import SessionManager
import datetime

logger = MyLogger.__call__().get_logger()


class ImportScanRestConsumer:
    def __init__(self, request: ImportScanRequest, session: SessionManager):
        self.__token = request.token_defect_dojo
        self.__host = request.host_defect_dojo
        self.__session = session

    def import_scan_api(self, request: ImportScanRequest):
        url = f"{self.__host}/api/v2/import-scan/"
        data = {
            "scan_date": request.scan_date,
            "minimum_severity": request.minimum_severity,
            "active": request.active,
            "verified": request.verified,
            "scan_type": request.scan_type,
            "endpoint_to_add": request.endpoint_to_add,
            # "file": request.file,
            "product_type_name": request.product_type_name,
            "product_name": request.product_name,
            "engagement_name": request.engagement_name,
            "engagement_end_date": "2023-02-23",
            "source_code_management_uri": request.source_code_management_uri,
            "engagement": str(request.engagement) if request.engagement != 0 else "",
            "auto_create_context": "false",
            "deduplication_on_engagement": request.deduplication_on_engagement,
            "lead": request.lead,
            "tags": request.tags,
            "close_old_findings": str(request.close_old_findings),
            "close_old_findings_product_scope": str(request.close_old_findings_product_scope),
            "push_to_jira": str(request.push_to_jira),
            "environment": request.environment,
            "version": request.version,
            "build_id": request.build_id,
            "branch_tag": request.branch_tag,
            "commit_hash": request.commit_hash,
            "api_scan_configuration": str(request.api_scan_configuration)
            if request.api_scan_configuration != 0
            else "",
            "service": request.service,
            "group_by": request.group_by,
        }
        logger.warning(data)
        multipart_data = MultipartEncoder(fields=data)

        headers = {"Authorization": f"Token {self.__token}", "Content-Type": multipart_data.content_type}
        response = self.__session.post(url, headers=headers, data=multipart_data, verify=VERIFY_CERTIFICATE)

        if response.status_code != 201:
            logger.error(response.status_code)
            logger.error(response.json())
            raise ValidationError(f"dojo: {response}")
        return response

    def import_scan(self, request: ImportScanRequest, files):
        url = f"{self.__host}/api/v2/import-scan/"
        payload = {
            "scan_date": request.scan_date,
            "minimum_severity": request.minimum_severity,
            "active": request.active,
            "verified": request.verified,
            "scan_type": request.scan_type,
            "endpoint_to_add": request.endpoint_to_add,
            "file": request.file,
            "product_type_name": request.product_type_name,
            "product_name": request.product_name,
            "engagement_name": request.engagement_name,
            "engagement_end_date": request.engagement_end_date,
            "source_code_management_uri": request.source_code_management_uri,
            "engagement": request.engagement if request.engagement != 0 else "",
            "auto_create_context": request.auto_create_context,
            "deduplication_on_engagement": request.deduplication_on_engagement,
            "lead": request.lead,
            "tags": request.tags,
            "close_old_findings": request.close_old_findings,
            "close_old_findings_product_scope": request.close_old_findings_product_scope,
            "push_to_jira": request.push_to_jira,
            "environment": request.environment,
            "version": request.version,
            "build_id": request.build_id,
            "branch_tag": request.branch_tag,
            "commit_hash": request.commit_hash,
            "api_scan_configuration": str(request.api_scan_configuration)
            if request.api_scan_configuration != 0
            else "",
            "service": request.service,
            "group_by": request.group_by,
        }

        headers = {"Authorization": f"Token {self.__token}"}

        response = self.__session.post(url, headers=headers, data=payload, files=files, verify=VERIFY_CERTIFICATE)

        if response.status_code != 201:
            logger.info(payload)
            logger.info(response.json())
            logger.error(response)
            raise ValidationError(response)
        logger.info(f"Sucessfull {response}")
        try:
            response = ImportScanRequest.from_dict(response.json())
        except Exception as e:
            logger.error(f"from dict import Scan: {response.json()}")
            raise ValidationError(e)
        return response
