from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck

class ALBListenerHTTPS(BaseResourceCheck):

    def __init__(self):
        name = "Ensure ELB V2 has Secure TargetGroup Protocol"
        id = "CKV_AWS_279"
        supported_resources = ['AWS::ElasticLoadBalancingV2::TargetGroup']
        categories = [CheckCategories.ENCRYPTION]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
 
        if 'Properties' in conf.keys():
            if 'Protocol' in conf['Properties'].keys():
                if conf['Properties']['Protocol'] in ('HTTPS', 'TLS', 'TCP'):
                    return CheckResult.PASSED
                    
        return CheckResult.FAILED

check = ALBListenerHTTPS()