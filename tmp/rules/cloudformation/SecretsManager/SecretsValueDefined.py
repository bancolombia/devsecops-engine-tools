
from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck


class SecretsValueDefined(BaseResourceCheck):
    def __init__(self):
        name = "Ensure that has Secret value is defined"
        id = "CKV_AWS_304"
        supported_resources = ['AWS::SecretsManager::Secret']
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):

        if 'Properties' in conf.keys():
            if 'GenerateSecretString' in conf['Properties'].keys() or 'SecretString' in conf['Properties'].keys():
                return CheckResult.PASSED
        return CheckResult.FAILED


check = SecretsValueDefined()