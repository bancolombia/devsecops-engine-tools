from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck

def is_not_empty(a):
    return len(a) > 0

class FSXEncryptionEnabled(BaseResourceCheck):
    def __init__(self):
        name = "Ensure FSX is encrypted at rest"
        id = "CKV_AWS_269"
        supported_resources = ['AWS::FSx::FileSystem']
        categories = [CheckCategories.ENCRYPTION]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)
    
    def scan_resource_conf(self, conf):
        if 'Properties' in conf.keys():
            if 'FileSystemType' in conf['Properties'].keys():
                if conf['Properties']['FileSystemType'] in ['LUSTRE','WINDOWS']:
                    if 'LustreConfiguration' in conf['Properties'].keys():
                        if 'DeploymentType' in conf['Properties']['LustreConfiguration']:
                            if 'PERSISTENT_1' not in conf['Properties']['LustreConfiguration']['DeploymentType']:
                                return CheckResult.UNKNOWN
                    if 'KmsKeyId' in conf['Properties'].keys() and is_not_empty(conf['Properties']['KmsKeyId']):
                        return CheckResult.PASSED
                else:
                    return CheckResult.UNKNOWN
        return CheckResult.FAILED
  
check = FSXEncryptionEnabled()
