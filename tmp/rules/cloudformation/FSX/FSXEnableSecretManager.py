from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck



class FSXEnableSecretManager(BaseResourceCheck):
    def __init__(self):
        name = "Ensure FSX has secret manager active"
        id = "CKV_AWS_359"
        supported_resources = ['AWS::FSx::FileSystem']
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)
    
    def scan_resource_conf(self, conf):
        if 'Properties' in conf.keys():
            if 'FileSystemType' in conf['Properties'].keys():
                 if conf['Properties']['FileSystemType'] == "WINDOWS":
                    if 'WindowsConfiguration' in conf['Properties'].keys():
                        if 'SelfManagedActiveDirectoryConfiguration' in conf['Properties']['WindowsConfiguration'].keys():
                            windowsConfiguration=conf['Properties']['WindowsConfiguration']
                            if 'Password' in windowsConfiguration['SelfManagedActiveDirectoryConfiguration'].keys():
                                    if -1 == str(windowsConfiguration['SelfManagedActiveDirectoryConfiguration']['Password']).find("resolve:secretsmanager"):
                                        return CheckResult.FAILED
                                    else:
                                        return CheckResult.PASSED
                            else:
                                    return CheckResult.FAILED
                        else:
                                return CheckResult.FAILED
                 else:
                        return CheckResult.SKIPPED
            else:
                return CheckResult.FAILED
        else:
             return CheckResult.SKIPPED
  
check = FSXEnableSecretManager()
