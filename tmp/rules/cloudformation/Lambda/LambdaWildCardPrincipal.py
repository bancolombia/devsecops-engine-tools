from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_value_check import BaseResourceCheck
from checkov.common.util.type_forcers import force_list

class LambdaWildCardPrincipal(BaseResourceCheck):
    def __init__ (self):
        name = "Ensure Lambda key policy doesnt contain wildcard (*) in principal"
        id = "CKV_AWS_315"
        supported_resources = ['AWS::Lambda::Permission']
        categories = [CheckCategories.ENCRYPTION]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self,conf):

        if conf.get('Properties'):
            policy_block =conf['Properties']
            if (policy_block['Action']=='*' or policy_block['Principal']=='*' or policy_block['Action']=='lambda:*'):
                return CheckResult.FAILED
            else:
                return CheckResult.PASSED


check = LambdaWildCardPrincipal()