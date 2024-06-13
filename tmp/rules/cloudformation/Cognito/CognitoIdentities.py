from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_value_check import BaseResourceCheck


class CognitoIdentities(BaseResourceCheck):
    def __init__(self):
        name = "Cognito has federated identities"
        id = "CKV_AWS_375"
        supported_resources = ['AWS::Cognito::IdentityPool']
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if 'Properties' in conf.keys():
            return CheckResult.FAILED

check = CognitoIdentities()