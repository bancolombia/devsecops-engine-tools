from typing import Any
from checkov.common.models.enums import CheckCategories
from checkov.cloudformation.checks.resource.base_resource_value_check import BaseResourceValueCheck

class APIGatewayTLS(BaseResourceValueCheck):

    def __init__(self):
        name = "Ensure that API Gateway Custom domain has TLS 1.2 or higher"
        id = "CKV_AWS_310"
        supported_resources = ['AWS::ApiGateway::DomainName']
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def get_inspected_key(self):
        return 'Properties/SecurityPolicy'

    def get_expected_value(self):
        return "TLS_1_2"

check = APIGatewayTLS()