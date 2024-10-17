import re
from devsecops_engine_tools.engine_utilities.utils.api_error import ApiError
from devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.cmdb import CmdbRestConsumer
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.request_objects.import_scan import ImportScanRequest
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities.azuredevops.infrastructure.azure_devops_api import AzureDevopsApi
from devsecops_engine_tools.engine_utilities.settings import SETTING_LOGGER

logger = MyLogger.__call__(**SETTING_LOGGER).get_logger()


class CmdbUserCase:
    def __init__(self, rest_consumer_cmdb: CmdbRestConsumer, utils_azure: AzureDevopsApi, expression) -> None:
        self.__rc_cmdb = rest_consumer_cmdb
        self.__utils_azure = utils_azure
        self.__expression = expression

    def execute(self, request: ImportScanRequest) -> ImportScanRequest:
        # Connection config map
        connection = self.__utils_azure.get_azure_connection()
        remote_config = self.__utils_azure.get_remote_json_config(connection=connection)

        # regular exprecion
        request.code_app = self.get_code_app(request.engagement_name)

        # connect cmdb
        product_data = self.__rc_cmdb.get_product_info(request)
        search_type_product = next(
            (
                key
                for key, list in remote_config.get("products_sync_with_other_productype", {}).items()
                if request.code_app in list
            ),
            None,
        )
        if search_type_product:
            request.product_type_name = search_type_product
        else:
            request.product_type_name = (
                remote_config["types_product"].get(product_data.product_type_name, product_data.product_type_name)
                if product_data.product_type_name
                else remote_config["types_product"].get("ORPHAN_PRODUCT_TYPE", "ORPHAN_PRODUCT_TYPE")
            )

        request.product_name = product_data.product_name
        request.product_description = product_data.product_description

        return request

    def get_code_app(self, engagement_name: str):
        m = re.search(r"" + self.__expression, engagement_name, re.IGNORECASE)
        if m is None:
            e = f"Engagement name {engagement_name} not match whit expression: {self.__expression}"
            logger.error(e)
            raise ApiError(e)
        code_app = m.group(1)
        logger.debug(code_app)
        return code_app.lower()
