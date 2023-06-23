import re
from helper.validation_error import ValidationError
from helper.logger_info import MyLogger
from defect_dojo.infraestructure.driver_adapters.\
    import_scan import ImportScanRestConsumer
from defect_dojo.infraestructure.driver_adapters.\
    product_type import ProductTypeRestConsumer
from defect_dojo.infraestructure.driver_adapters.\
    product import ProductRestConsumer
from defect_dojo.infraestructure.driver_adapters.\
    scan_configurations import ScanConfigrationRestConsumer
from defect_dojo.domain.request_objects.import_scan\
    import ImportScanRequest
logger = MyLogger.__call__().get_logger()


class ImportScanUserCase:

    def __init__(self, rest_import_scan: ImportScanRestConsumer,
                 rest_product_type: ProductTypeRestConsumer,
                 rest_product: ProductRestConsumer,
                 rest_scan_configuration: ScanConfigrationRestConsumer):

        self.__rest_import_scan = rest_import_scan
        self.__rest_product_type = rest_product_type
        self.__rest_product = rest_product
        self.__rest_scan_configurations = rest_scan_configuration

    def execute(self, request: ImportScanRequest) -> ImportScanRequest:
        product_type_id = None
        product_id = None
        tools_configurations = 1

        if (request.product_name or request.product_type_name) == "":
            logger.error("Name product not found")
            raise ValidationError("Name product not found")

        if re.search(" API ", request.scan_type):
            logger.info(f"Match {request.scan_type}")
            product_types = self.__rest_product_type.get_product_types(request)
            if product_types.results == []:
                product_type = self.__rest_product_type.\
                    post_product_type(request)
                product_type_id = product_type
                logger.info(f"product_type created: {product_type.name} with id {product_type.id}")
            else:
                product_type_id = product_types.results[0].id
                logger.info(
                    f"product_type found: {product_types.results[0].name}\
                        with id {product_id}"
                    )

            products = self.__rest_product.get_products(request)
            if products.results == []:
                product = self.__rest_product.post_product(
                    request,
                    product_type_id)
                product_id = product.id
                logger.info(
                    f"product created: {product.name}\
                        found with id: {product.id}")
            else:
                product_id = products.results[0].id
                logger.info(f"product found: {request.product_name}\
                    with id: {product_id}")
           
            scan_configuration = self.__rest_scan_configurations\
                .post_api_scan_configuration(request,
                                             product_id,
                                             tools_configurations)

            request.api_scan_configuration = scan_configuration.id

            response = self.__rest_import_scan.import_scan_api(request)
            logger.info(f"End process Succesfull!!!: {response}")
            return response
        else:
            try:
                with open(request.file, 'rb') as file:
                    logger.info("read file succesfull !!!")
                    files = [('file', ("name_file", file, 'application'))]
                    return self.__rest_import_scan.import_scan(request, files)
            except Exception as e:
                logger.error(e)