from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck

class BatchNotHighPrivileges(BaseResourceCheck):
    
    def __init__(self):
        name = "Ensure batch has not high privileges"
        id = "CKV_AWS_368"
        supported_resources = ['AWS::Batch::JobDefinition']
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):

        if 'Properties' in conf.keys():
            if 'Type' in conf['Properties'].keys():
                if str(conf['Properties']['Type']).lower()=='container':
                    if 'ContainerProperties' in conf['Properties'].keys():
                        if 'Privileged' in conf['Properties']['ContainerProperties']:
                            container=conf['Properties']['ContainerProperties']
                            if str(container['Privileged']).lower() == 'true':
                                return CheckResult.FAILED
                            else:
                                return CheckResult.PASSED
                        else:
                            return CheckResult.PASSED
                else:
                    return CheckResult.PASSED
            else:
                return CheckResult.UNKNOWN
check = BatchNotHighPrivileges()

