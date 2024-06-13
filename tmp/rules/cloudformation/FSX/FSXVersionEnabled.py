from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck

class FSXVersionEnabled(BaseResourceCheck):
    def __init__(self):
        name = "Ensure FSX version is enabled by the bank"
        id = "CKV_AWS_354"
        supported_resources = ['AWS::FSx::FileSystem']
        categories = [CheckCategories.ENCRYPTION]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)
    
    def scan_resource_conf(self, conf):
        if 'Properties' in conf.keys():
            if 'FileSystemType' in conf['Properties'].keys():
                if conf['Properties']['FileSystemType'] != 'ONTAP':
                    return CheckResult.PASSED
        return CheckResult.FAILED
    
check = FSXVersionEnabled()  