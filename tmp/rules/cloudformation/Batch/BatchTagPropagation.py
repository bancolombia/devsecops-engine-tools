from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck

class BatchTagPropagation(BaseResourceCheck):
    
    def __init__(self):
        name = "Ensure batch has tag propagation enabled"
        id = "CKV_AWS_364"
        supported_resources = ['AWS::Batch::JobDefinition']
        categories = [CheckCategories.SUPPLY_CHAIN]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):

        if 'Properties' in conf.keys():
            if 'PropagateTags' in conf['Properties'].keys():
                if str(conf['Properties']['PropagateTags']).lower()=='true':
                    return CheckResult.PASSED
                else:
                    return CheckResult.FAILED
            else:
                return CheckResult.FAILED
check = BatchTagPropagation()

