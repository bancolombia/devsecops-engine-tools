import re
import os
import urllib3
from devsecops_engine_tools.engine_utilities.settings import SETTING_LOGGER
from devsecops_engine_tools.engine_utilities.utils.api_error import ApiError
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.import_scan import ImportScanRestConsumer
from devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.product_type import ProductTypeRestConsumer
from devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.product import ProductRestConsumer
from devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.scan_configurations import (
    ScanConfigrationRestConsumer)
from devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.engagement import EngagementRestConsumer
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.request_objects.import_scan import ImportScanRequest

logger = MyLogger.__call__(**SETTING_LOGGER).get_logger()

urllib3.disable_warnings()


class ImportScanUserCase:
    def __init__(
        self,
        rest_import_scan: ImportScanRestConsumer,
        rest_product_type: ProductTypeRestConsumer,
        rest_product: ProductRestConsumer,
        rest_scan_configuration: ScanConfigrationRestConsumer,
        rest_engagement: EngagementRestConsumer,

    ):
        self.__rest_import_scan = rest_import_scan
        self.__rest_product_type = rest_product_type
        self.__rest_product = rest_product
        self.__rest_scan_configurations = rest_scan_configuration
        self.__rest_engagement = rest_engagement

    def get_file_type(self, path_file):
        __, extension = os.path.splitext(path_file)
        dict_rule_type_file = {
            ".csv": "text/csv",
            ".json": "apllication/json",
            ".xml": "aplication/xml",
            ".sarif": "aplication/json",
        }
        file_type = dict_rule_type_file.get(extension)
        return file_type

    def import_scan(self, request, api_scan_bool):
        response = None
        if api_scan_bool:
            response = self.__rest_import_scan.import_scan_api(request)
            logger.debug(f"End process Succesfull!!!: {response}")
        else:
            try:
                file_type = self.get_file_type(request.file)
                if file_type is None:
                    raise ApiError("File format not allowed")

                with open(request.file, "rb") as file:
                    logger.debug(f"read {file_type} file successful !!!")
                    files = [("file", (request.file, file, file_type))]
                    response = self.__rest_import_scan.import_scan(request, files)

            except Exception as e:
                if "504 Gateway Time-out" in str(e):
                    logger.warning("Timeout balancer response, Vulnerability management keep Processing Import Scan in Background")
                    response = ImportScanRequest()
                    response.url = f"{request.host_defect_dojo}"
                    return response
                logger.error(f"from dict import Scan: {e}")
                raise ApiError(e)

        response.url = f"{request.host_defect_dojo}/test/{str(response.test_id)}"
        return response

    def execute(self, request: ImportScanRequest) -> ImportScanRequest:
        product_id = None
        
        if (request.product_name or request.product_type_name) == "":
            log = f"Name product {request.product_name} or product type {request.product_type_name} is empty"
            logger.error(log)
            raise ApiError(log)

        logger.debug(f"Match {request.scan_type}")
        searchTypeKey = "name_exact" if request.get_exact_product is True else "name"
        products = self.__rest_product.get_products({searchTypeKey: request.product_name})
        if len(products.results) == 0 and request.product_name != "Orphan_Product":
            products = self.__rest_product.get_products({searchTypeKey: request.code_app})
        if len(products.results) > 0:
            product_id = products.results[0].id
            request.product_name = products.results[0].name
            request.product_type_name = self.__rest_product_type.get_product_type_id(products.results[0].prod_type).name
            logger.debug(f"product found: {request.product_name} with id: {product_id}")
        else:
            product_type_id = None
            product_types = self.__rest_product_type.get_product_types(request.product_type_name)
            if product_types.results == []:
                product_type = self.__rest_product_type.post_product_type(request.product_type_name)
                product_type_id = product_type.id
                logger.debug(f"product_type created: {product_type.name} with id {product_type.id}")
            else:
                if len(product_types.results) != 1:
                    logger.warning(f"there is more than one product type with the name: {product_types.results}")

                product_type_id = product_types.results[0].id
                logger.debug(
                    f"product_type found: {product_types.results[0].name}\
                        with id {product_type_id}"
                )

            product = self.__rest_product.post_product(request, product_type_id)
            product_id = product.id
            logger.debug(
                f"product created: {product.name}\
                    found with id: {product.id}"
            )

        api_scan_bool = re.search(" API ", request.scan_type)
        if api_scan_bool:
            scan_configuration_list = self.__rest_scan_configurations.get_api_scan_configuration(request, product_id)
            if scan_configuration_list.results == []:
                scan_configuration = self.__rest_scan_configurations.post_api_scan_configuration(
                    request, product_id, request.tool_sonarqube_configuration
                )
                request.api_scan_configuration = scan_configuration.id
                logger.debug(f"Scan configuration create service_key_1 : {scan_configuration.service_key_1}")
            else:
                logger.debug(
                    f"Scan configuration found service_key: {scan_configuration_list.results[0].service_key_1}"
                )
                request.api_scan_configuration = scan_configuration_list.results[0].id

        logger.debug(f"search Engagement name: {request.engagement_name}")
        engagement = self.__rest_engagement.get_engagements(request.engagement_name)
        if engagement.results == [] or not any(engagement.name == request.engagement_name for engagement in engagement.results):
            engagement = self.__rest_engagement.post_engagement(request, product_id, request.tool_scm_configuration)
            logger.debug(f"Engagement created: {engagement.name}")
        else:
            if request.hold_found_product_engagement:
                engagement = [engagement for engagement in engagement.results if engagement.name == request.engagement_name]
            else:
                engagement = [engagement for engagement in engagement.results if engagement.product == product_id and engagement.name == request.engagement_name]

            if engagement:
                logger.debug(f"Engagement found: {engagement[0].name} whit product id: {engagement[0].product}")
                if request.hold_found_product_engagement and product_id != engagement[0].product:
                    product_engagement = self.__rest_product.get_products({"id": engagement[0].product, "prefetch": "prod_type"})
                    if len(product_engagement.results) > 0:
                        product_eng = product_engagement.results[0]
                        request.product_name = product_eng.name
                        request.product_type_name = product_engagement.prefetch.prod_type[str(product_eng.prod_type)].name
                        logger.debug(f"Hold Product engagement found: {request.product_name} with product type: {request.product_type_name}")
                description_changed = request.engagement_description and engagement[0].description != request.engagement_description
                scm_uri_changed = request.source_code_management_uri and engagement[0].source_code_management_uri != request.source_code_management_uri
                scm_server_changed = request.tool_scm_configuration and str(engagement[0].source_code_management_server) != str(request.tool_scm_configuration)
                if description_changed or scm_uri_changed or scm_server_changed:
                    engagement = self.__rest_engagement.patch_engagement(request, engagement[0].id, request.tool_scm_configuration)
                    logger.debug(f"Engagement updated: {engagement.name}")

            else:
                engagement = self.__rest_engagement.post_engagement(request, product_id, request.tool_scm_configuration)
                logger.debug(f"Engagement created: {engagement.name} whit product id {engagement.product}")

        return self.import_scan(request, api_scan_bool)
