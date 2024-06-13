from typing import List
from checkov.cloudformation.checks.resource.base_resource_value_check import BaseResourceCheck
from checkov.common.models.enums import CheckCategories, CheckResult

class MongoDBSecretManager(BaseResourceCheck):

    def __init__(self):
        name = "Ensure MongoDB has enable data rest encryption"
        id = "CKV_AWS_386"
        supported_resources = ['MongoDB::Atlas::Cluster']
        categories = [CheckCategories.ENCRYPTION]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if 'Properties' in conf.keys():
            if 'ApiKeys' in conf['Properties'].keys():
                apikeys=conf['Properties']['ApiKeys']
                if "PublicKey" in apikeys.keys() and "resolve:secretsmanager:" in str(apikeys["PublicKey"]) and "PrivateKey" in apikeys.keys() and "resolve:secretsmanager:" in str(apikeys["PrivateKey"]):
                    return CheckResult.PASSED
            else: 
                return CheckResult.FAILED
        return CheckResult.FAILED


check = MongoDBSecretManager()
