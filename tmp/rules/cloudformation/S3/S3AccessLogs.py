from typing import Any,List

from checkov.cloudformation.checks.resource.base_resource_value_check import BaseResourceValueCheck
from checkov.common.models.enums import CheckCategories,CheckResult


class S3AccessLogs(BaseResourceValueCheck):
    def __init__(self):
        name = "Ensure the S3 bucket has access logging enabled"
        id = "CKV_AWS_267"
        supported_resources = ['AWS::S3::Bucket']
        categories = [CheckCategories.LOGGING]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        properties = conf.get('Properties')
        if properties is not None:
            access_control = properties.get('AccessControl')
            if access_control is not None:
                if "Private" not in access_control:
                    return CheckResult.UNKNOWN
            logging_configuration = properties.get('LoggingConfiguration')
            if logging_configuration is not None:
                return CheckResult.PASSED
        return CheckResult.FAILED

    def get_inspected_key(self) -> List[str]:
        return ["Properties/LoggingConfiguration","Properties/AccessControl"]


check = S3AccessLogs()