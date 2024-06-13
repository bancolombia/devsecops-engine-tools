from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck


class EC2DeletionProtection(BaseResourceCheck):
    def __init__(self):
        name = "EC2 instance has deletion protection disabled"
        id = "CKV_AWS_277"
        supported_resources = ['AWS::EC2::Instance']
        categories = [CheckCategories.BACKUP_AND_RECOVERY]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if 'Properties' in conf.keys():
            if 'DisableApiTermination' in conf['Properties'].keys():
                if "true" in str(conf['Properties']['DisableApiTermination']).lower():
                    return CheckResult.PASSED

        return CheckResult.FAILED

check = EC2DeletionProtection()
