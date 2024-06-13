from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck

class BatchSecurityGroup(BaseResourceCheck):
    
    def __init__(self):
        name = "Ensure batch has security groups"
        id = "CKV_AWS_363"
        supported_resources = ['AWS::Batch::ComputeEnvironment']
        categories = [CheckCategories.NETWORKING]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):

        if 'Properties' in conf.keys():
            if 'ComputeResources' in conf['Properties'].keys():
                if 'SecurityGroupIds' in conf['Properties']['ComputeResources'].keys():
                    return CheckResult.PASSED
                else:
                    return CheckResult.FAILED
check = BatchSecurityGroup()

