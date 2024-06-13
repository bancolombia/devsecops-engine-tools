from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck

class TransferFamilyUser(BaseResourceCheck):
    def __init__(self):
        name = "Rule that controls the deployment of the resource User"
        id = "CKV_AWS_407"
        supported_resources = ['AWS::Transfer::User']
        categories = [CheckCategories.CONVENTION]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if 'Properties' in conf.keys():
            if 'Name' in conf['Properties'].keys():
                return CheckResult.FAILED
        return CheckResult.PASSED
check = TransferFamilyUser()
