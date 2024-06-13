from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck

class FSXMultiAZ(BaseResourceCheck):
    def __init__(self):
        name = "Ensure FSX WindowsConfiguration deploymentType uses MULTI_AZ_1"
        id = "CKV_AWS_355"
        supported_resources = ['AWS::FSx::FileSystem']
        categories = [CheckCategories.ENCRYPTION]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)
    
    def scan_resource_conf(self, conf):
        if 'Properties' in conf.keys():
            if 'FileSystemType' in conf['Properties'].keys():
                if conf['Properties']['FileSystemType'] == 'WINDOWS':
                        if 'WindowsConfiguration' in conf['Properties']:
                            if 'DeploymentType' in conf['Properties']['WindowsConfiguration']:
                                 if conf['Properties']['WindowsConfiguration']['DeploymentType'] == 'MULTI_AZ_1':    
                                    return CheckResult.PASSED
                else:
                    return CheckResult.UNKNOWN
        return CheckResult.FAILED
    
check = FSXMultiAZ()  