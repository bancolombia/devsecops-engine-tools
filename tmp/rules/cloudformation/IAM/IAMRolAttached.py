from typing import Any

from checkov.cloudformation.checks.resource.base_resource_value_check import BaseResourceValueCheck
from checkov.common.models.consts import ANY_VALUE
from checkov.common.models.enums import CheckCategories


class IAMRolAttached(BaseResourceValueCheck):
    def __init__(self):
        name = "Ensure the has IAM Policy has attached Roles"
        id = "CKV_AWS_299"
        supported_resources = ['AWS::IAM::Policy']
        categories = [CheckCategories.IAM]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def get_inspected_key(self) -> str:
        return "Properties/Roles"

    def get_expected_value(self) -> Any:
        return ANY_VALUE


check = IAMRolAttached()