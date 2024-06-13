from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck

class EBSDeleteOnTerminationLaunch(BaseResourceCheck):
    def __init__(self):
        name = "Ensure EBS has not delete on termination in launch template"
        id = "CKV_AWS_328"
        supported_resources = ['AWS::EC2::Instance']
        categories = [CheckCategories.BACKUP_AND_RECOVERY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if 'Properties' in conf.keys():
            if 'BlockDeviceMappings' in conf['Properties'].keys():
                if isinstance(conf['Properties']['BlockDeviceMappings'], list):
                    for block_device_mappings in conf['Properties']['BlockDeviceMappings']:
                        if 'Ebs' in block_device_mappings.keys():
                            if isinstance( block_device_mappings['Ebs'], dict) and 'DeleteOnTermination' in block_device_mappings['Ebs'].keys():
                                if str(block_device_mappings['Ebs']['DeleteOnTermination']).lower()== "false":
                                    return CheckResult.PASSED
        return CheckResult.FAILED

check = EBSDeleteOnTerminationLaunch()