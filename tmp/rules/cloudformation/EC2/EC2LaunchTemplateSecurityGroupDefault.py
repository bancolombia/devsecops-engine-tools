from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck


class EC2LaunchTemplateSecurityGroupDefault(BaseResourceCheck):
    def __init__(self):
        name = "EC2 LaunchTemplate use Security Group default"
        id = "CKV_AWS_290"
        supported_resources = ['AWS::EC2::LaunchTemplate']
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if 'Properties' in conf.keys():
            if 'LaunchTemplateData' in conf['Properties'].keys():
                if "SecurityGroupIds" in conf['Properties']['LaunchTemplateData'].keys():
                    return CheckResult.PASSED
                elif "SecurityGroups" in conf['Properties']['LaunchTemplateData'].keys():
                    return CheckResult.PASSED
                elif 'NetworkInterfaces' in conf['Properties']['LaunchTemplateData'].keys():
                    if isinstance(conf['Properties']['LaunchTemplateData']['NetworkInterfaces'], list):
                        for item in conf['Properties']['LaunchTemplateData']['NetworkInterfaces']:
                            if 'Groups' not in item.keys():
                                return CheckResult.FAILED
                        return CheckResult.PASSED

        return CheckResult.FAILED

check = EC2LaunchTemplateSecurityGroupDefault()
