from typing import Any

from checkov.common.models.enums import CheckCategories
from checkov.cloudformation.checks.resource.base_resource_value_check import BaseResourceValueCheck
from checkov.common.models.consts import ANY_VALUE


class EC2ServiceRole(BaseResourceValueCheck):
    def __init__(self):
        name = "Ensure EC2 instance has service rol associated"
        id = "CKV_AWS_298"
        supported_resources = ['AWS::EC2::Instance']
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def get_inspected_key(self):
        return 'Properties/IamInstanceProfile'

    def get_expected_value(self) -> Any:
        return ANY_VALUE

check = EC2ServiceRole()