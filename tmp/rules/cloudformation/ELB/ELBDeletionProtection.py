from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck


class ELBDeletionProtection(BaseResourceCheck):

    def __init__(self):
        name = "Ensure ELB has deletion protection disabled"
        id = "CKV_AWS_276"
        supported_resources = ['AWS::ElasticLoadBalancingV2::LoadBalancer']
        categories = [CheckCategories.BACKUP_AND_RECOVERY]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if 'Properties' in conf.keys():
            if 'LoadBalancerAttributes' in conf['Properties'].keys():
                loadBalancerAttributes = [] 
                if 'Fn::If' in conf['Properties']['LoadBalancerAttributes']:
                    listFnIf = conf['Properties']['LoadBalancerAttributes']['Fn::If']
                    position = 1
                    if 'notPdn' in listFnIf[0]:
                        position = 2
                    loadBalancerAttributes = listFnIf[position]
                else:
                    loadBalancerAttributes = conf['Properties']['LoadBalancerAttributes']
                return checkDeletionProtection(loadBalancerAttributes)
        return CheckResult.FAILED


check = ELBDeletionProtection()


def checkDeletionProtection(loadBalancerAttributes):
    if isinstance(loadBalancerAttributes, list):
        for item in loadBalancerAttributes:
            if 'Key' in item.keys() and 'Value' in item.keys():
                if item['Key'] == "deletion_protection.enabled" and "true" in str(item['Value']).lower():
                    return CheckResult.PASSED
    return CheckResult.FAILED
