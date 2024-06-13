from typing import List
from checkov.cloudformation.checks.resource.base_resource_value_check import BaseResourceCheck
from checkov.common.models.enums import CheckCategories, CheckResult

class NeptuneEncryptionRest(BaseResourceCheck):

    def __init__(self):
        name = "Ensure Neptune has enable data rest encryption"
        id = "CKV_AWS_379"
        supported_resources = ['AWS::Neptune::DBCluster']
        categories = [CheckCategories.ENCRYPTION]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if 'Properties' in conf.keys():
            if 'KmsKeyId' in conf['Properties'].keys() and 'StorageEncrypted' in conf['Properties'].keys() and str(conf['Properties']['StorageEncrypted']) == "True":
                return CheckResult.PASSED
            else: 
                return CheckResult.FAILED
        return CheckResult.FAILED


check = NeptuneEncryptionRest()
