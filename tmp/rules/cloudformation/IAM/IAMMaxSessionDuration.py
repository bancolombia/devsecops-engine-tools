
from checkov.cloudformation.checks.resource.base_resource_value_check import BaseResourceCheck
from checkov.common.models.enums import CheckCategories, CheckResult

class IAMMaxSessionDuration(BaseResourceCheck):
    def __init__(self):
        name = "Ensure iam Max session duration"
        id = "CKV_AWS_374"
        supported_resources = ['AWS::IAM::Role']
        categories = [CheckCategories.IAM]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if 'Properties' in conf.keys():
            if 'MaxSessionDuration' in conf['Properties'].keys():
                if conf['Properties']['MaxSessionDuration'] <= 3600 :
                    return CheckResult.PASSED
                else:
                    return CheckResult.FAILED
            return CheckResult.PASSED


check = IAMMaxSessionDuration()