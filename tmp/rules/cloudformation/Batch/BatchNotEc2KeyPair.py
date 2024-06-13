from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck

class BatchNotEc2KeyPair(BaseResourceCheck):
    
    def __init__(self):
        name = "Ensure batch has not Ec2KeyPair"
        id = "CKV_AWS_369"
        supported_resources = ['AWS::Batch::ComputeEnvironment']
        categories = [CheckCategories.NETWORKING]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):

        if 'Properties' in conf.keys():
            if 'ComputeResources' in conf['Properties'].keys():
                if 'Ec2KeyPair' in conf['Properties']['ComputeResources'].keys():
                    return CheckResult.FAILED
                else:
                    return CheckResult.PASSED

check = BatchNotEc2KeyPair()

