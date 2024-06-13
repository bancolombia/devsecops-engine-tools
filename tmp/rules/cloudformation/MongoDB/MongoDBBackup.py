from typing import List
from checkov.cloudformation.checks.resource.base_resource_value_check import BaseResourceCheck
from checkov.common.models.enums import CheckCategories, CheckResult

class MongoDBBackup(BaseResourceCheck):

    def __init__(self):
        name = "Ensure MongoDB has backup configuration"
        id = "CKV_AWS_384"
        supported_resources = ['MongoDB::Atlas::Cluster']
        categories = [CheckCategories.ENCRYPTION]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if 'Properties' in conf.keys():
            if 'ProviderBackupEnabled' in conf['Properties'].keys() and str(conf['Properties']['ProviderBackupEnabled']) == "True":
                return CheckResult.PASSED
            else: 
                return CheckResult.FAILED
        return CheckResult.FAILED


check = MongoDBBackup()
