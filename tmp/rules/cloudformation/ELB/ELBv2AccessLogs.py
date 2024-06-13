from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck


class ELBv2AccessLogs(BaseResourceCheck):
    def __init__(self):
        name = "Ensure the ELBv2 (Application/Network) has access logging enabled"
        id = "CKV_AWS_266"
        supported_resources = ['AWS::ElasticLoadBalancingV2::LoadBalancer']
        categories = [CheckCategories.LOGGING]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if 'Properties' in conf.keys():
            if 'Type' in conf['Properties'].keys():
                if "network" in conf['Properties']['Type']:
                    return CheckResult.UNKNOWN
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
                return checkAccessLogs(loadBalancerAttributes)
        return CheckResult.FAILED


check = ELBv2AccessLogs()


def checkAccessLogs(loadBalancerAttributes):
    if isinstance(loadBalancerAttributes, list):
        for item in loadBalancerAttributes:
            if 'Key' in item.keys() and 'Value' in item.keys():
                if item['Key'] == "access_logs.s3.enabled" and "true" in str(item['Value']).lower():
                    return CheckResult.PASSED
    return CheckResult.FAILED
