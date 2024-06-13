from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck

class ALBSecurityGroups(BaseResourceCheck):
    def __init__(self):
        name = "Ensure ALB has security groups"
        id = "CKV_AWS_396"
        supported_resources = ['AWS::ElasticLoadBalancingV2::LoadBalancer']
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if 'Properties' in conf.keys():
            if 'SecurityGroups' in conf['Properties'].keys():
                if conf['Properties']['SecurityGroups']:
                    return CheckResult.PASSED
        return CheckResult.FAILED
    
check = ALBSecurityGroups()