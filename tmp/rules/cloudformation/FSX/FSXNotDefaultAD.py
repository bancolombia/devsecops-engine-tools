from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck

def is_not_empty(a):
    return len(a) > 0

class FSXNotDefaultAD(BaseResourceCheck):
    def __init__(self):
        name = "Ensure FSX has not default AD"
        id = "CKV_AWS_349"
        supported_resources = ['AWS::FSx::FileSystem']
        categories = [CheckCategories.ENCRYPTION]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)
    
    def scan_resource_conf(self, conf):
        if 'Properties' in conf.keys():
            if 'FileSystemType' in conf['Properties'].keys():
                if conf['Properties']['FileSystemType'] == 'WINDOWS':
                    if 'WindowsConfiguration' in conf['Properties'].keys():
                        if 'ActiveDirectoryId' in conf['Properties']['WindowsConfiguration'].keys():
                            return CheckResult.FAILED
                        else:
                            return CheckResult.PASSED
                else :
                    return CheckResult.SKIPPED        
        return CheckResult.PASSED
  
check = FSXNotDefaultAD()
