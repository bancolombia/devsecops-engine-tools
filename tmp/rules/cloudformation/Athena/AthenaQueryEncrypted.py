from pickle import TRUE
from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck

class AthenaQueryEncrypted(BaseResourceCheck):
    def __init__(self):
        name = "Ensure Athena query encrypted"
        id = "CKV_AWS_325"
        supported_resources = ['AWS::Athena::WorkGroup']
        categories = [CheckCategories.ENCRYPTION]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if 'Properties' in conf.keys():
            if 'WorkGroupConfiguration' in conf['Properties'].keys():
                policy_block = conf['Properties']['WorkGroupConfiguration']
                if("ResultConfiguration" in policy_block.keys()):
                    if("EncryptionConfiguration" in policy_block["ResultConfiguration"]):
                        if("KmsKey" in policy_block["ResultConfiguration"]["EncryptionConfiguration"].keys()):
                            return CheckResult.PASSED
                    return CheckResult.FAILED

check = AthenaQueryEncrypted()