from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck


class DocumentDBEncryptionRest(BaseResourceCheck):
    def __init__(self):
        name = "Ensure documentDB has encryption at rest"
        id = "CKV_AWS_351"
        supported_resources = ['AWS::DocDB::DBCluster']
        categories = [CheckCategories.ENCRYPTION]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if 'Properties' in conf.keys():
            if 'KmsKeyId' in conf['Properties'].keys():
                return CheckResult.PASSED
        return CheckResult.FAILED  

check = DocumentDBEncryptionRest()  