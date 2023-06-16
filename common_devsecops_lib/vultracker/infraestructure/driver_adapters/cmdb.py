import json
import requests
from devsecops_lib.helper.logger_info import MyLogger
from devsecops_lib.helper.validation_error import ValidationError
from devsecops_lib.vultracker.domain.request_objects.import_scan import ImportScanRequest
from devsecops_lib.vultracker.domain.models.cmdb import Cmdb
from devsecops_lib.vultracker.infraestructure.driver_adapters.settings.settings import VERIFY_CERTIFICATE
logger = MyLogger.__call__().get_logger()


class CmdbRestConsumer:

    def __init__(self, request: ImportScanRequest, token: str, host: str) -> None:
        self.__token = token
        self.__host = host

    def get_product_info(self, request: ImportScanRequest) -> Cmdb:

        data = json.dumps({"codapp": request.code_app})
        headers = {
            "tokenkey": self.__token,
            "Content-Type": "application/json"}

        logger.info("Search info of name product")
        response = requests.request(
            "POST",
            self.__host,
            headers=headers,
            data=data,
            verify=VERIFY_CERTIFICATE)

        if response.status_code != 200:
            logger.error(response)
            raise ValidationError(response)
        if response.json() == []:
            logger.error(f"Engagement: {request.code_app} not found")
            raise ValidationError("Engagement not found")
        data = response.json()[0]
        data_map = {
            "product_type_name": data["nombreevc"],
            "product_name": data["nombreapp"],
            "tag_product": data["nombreentorno"],
            "product_description": data["arearesponsableti"],
            "codigo_app": data["CodigoApp"]}

        cmdb_object = Cmdb.from_dict(data_map)
        return cmdb_object

