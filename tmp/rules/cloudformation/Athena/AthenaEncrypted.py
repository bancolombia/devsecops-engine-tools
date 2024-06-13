from pickle import TRUE
from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck

class AthenaEncrypted(BaseResourceCheck):
    def __init__(self):
        name = "Ensure Athena encrypted"
        id = "CKV_AWS_324"
        supported_resources = ['AWS::Athena::WorkGroup']
        categories = [CheckCategories.ENCRYPTION]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if 'Properties' in conf.keys():
            if 'WorkGroupConfiguration' in conf['Properties'].keys():
                policy_block = conf['Properties']['WorkGroupConfiguration']
                if("EnforceWorkGroupConfiguration" in policy_block.keys()):
                    if(policy_block["EnforceWorkGroupConfiguration"] in ["true",True]):
                        return CheckResult.PASSED
        return CheckResult.FAILED

check = AthenaEncrypted()
