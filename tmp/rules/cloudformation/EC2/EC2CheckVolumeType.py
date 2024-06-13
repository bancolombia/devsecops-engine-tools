from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck

class CheckVolumenType(BaseResourceCheck):
    def __init__(self):
        name = "Rules that control the deployment of type resources gp2"
        id = "CKV_AWS_408"
        supported_resources = ['AWS::EC2::Volume']
        categories = [CheckCategories.CONVENTION]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if 'Properties' in conf.keys():
            if 'VolumeType' in conf['Properties'].keys():
                if 'gp2' in conf['Properties']['VolumeType']:
                    return CheckResult.FAILED
                else:
                    return CheckResult.PASSED
        return CheckResult.FAILED
    
check = CheckVolumenType()
