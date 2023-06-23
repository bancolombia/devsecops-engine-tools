import requests
from requests_toolbelt.multipart.encoder import MultipartEncoder
from defect_dojo.domain.request_objects.import_scan import ImportScanRequest
from helper.logger_info import MyLogger
from helper.validation_error import ValidationError
from defect_dojo.infraestructure.driver_adapters.settings.settings import VERIFY_CERTIFICATE

logger = MyLogger.__call__().get_logger()


class ImportScanRestConsumer:
    def __init__(self, request: ImportScanRequest):
        self.__token = request.token_vultracker
        self.__host = request.host_vultracker

    def import_scan_api(self, request: ImportScanRequest):
        url = f"{self.__host}/api/v2/import-scan/"
        data = {
            "active": request.active,
            "verified": request.verified,
            "scan_type": request.scan_type,
            "product_name": request.product_name,
            "engagement_name": request.engagement_name,
            "auto_create_context": request.auto_create_context,
            "product_type_name": request.product_type_name,
            "api_scan_configuration": str(request.api_scan_configuration),
        }
        multipart_data = MultipartEncoder(fields=data)

        headers = {"Authorization": f"Token {self.__token}", "Content-Type": multipart_data.content_type}
        response = requests.post(url, headers=headers, data=multipart_data, verify=VERIFY_CERTIFICATE)

        if response.status_code != 201:
            logger.error(response.json())
            raise ValidationError(response.json())
        response = ImportScanRequest.from_dict(response)
        return response

    def import_scan(self, request: ImportScanRequest, files):
        url = f"{self.__host}/api/v2/import-scan/"
        payload = {
            "active": request.active,
            "verified": request.verified,
            "scan_type": request.scan_type,
            "product_name": request.product_name,
            "engagement_name": request.engagement_name,
            "auto_create_context": request.auto_create_context,
            "product_type_name": request.product_type_name,
        }

        headers = {"Authorization": f"Token {self.__token}"}

        response = requests.request("POST", url, headers=headers, data=payload, files=files, verify=VERIFY_CERTIFICATE)
        if response.status_code != 201:
            logger.info(payload)
            logger.info(response.json())
            logger.error(response)
            raise ValidationError(response)
        logger.info(f"Sucessfull {response}")
        response = ImportScanRequest.from_dict(response.json())
        return response
