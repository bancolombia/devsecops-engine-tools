from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck

import re

class EC2DeleteOnTermination(BaseResourceCheck):
    def __init__(self):
        name = "Enable delete on termination for associate EBS"
        id = "CKV_AWS_405"
        supported_resources = ['AWS::EC2::Instance','AWS::AutoScaling::LaunchConfiguration','AWS::EC2::LaunchTemplate']
        categories = [CheckCategories.BACKUP_AND_RECOVERY]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if 'Properties' in conf.keys():
            if 'BlockDeviceMappings' in conf['Properties'].keys():
                try:
                    for device in conf['Properties']['BlockDeviceMappings']:
                        if 'VirtualName' not in device.keys():
                            if re.search(r'^\/dev\/(sd|xvd)[b-z]', device['DeviceName']):
                                if 'true' in str(device['Ebs']['DeleteOnTermination']).lower():
                                    return CheckResult.PASSED
                                else:
                                    return CheckResult.FAILED
                    return CheckResult.PASSED
                except Exception:
                    return CheckResult.FAILED
            return CheckResult.PASSED
        return CheckResult.FAILED
    
check = EC2DeleteOnTermination()
