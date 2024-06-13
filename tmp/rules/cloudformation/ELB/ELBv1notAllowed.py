from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_value_check import BaseResourceCheck


class ELBv1notAllowed(BaseResourceCheck):
    def __init__(self):
        name = "ELB v1 isn't permited"
        id = "CKV_AWS_278"
        supported_resources = ['AWS::ElasticLoadBalancing::LoadBalancer']
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if 'Properties' in conf.keys():
            return CheckResult.FAILED

check = ELBv1notAllowed()