from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck
import re


class FSXFileSystemAdministrator(BaseResourceCheck):
    def __init__(self):
        name = "Ensure FSX has bank active directory"
        id = "CKV_AWS_358"
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
                            if 'FileSystemAdministratorsGroup' in windowsConfiguration['SelfManagedActiveDirectoryConfiguration'].keys():
                                    pattern = r"^R_FSX.*_AWS$"
                                    match = re.search(pattern, str(windowsConfiguration['SelfManagedActiveDirectoryConfiguration']['FileSystemAdministratorsGroup']))
                                    if match:
                                        return CheckResult.PASSED
                                    else:
                                        return CheckResult.FAILED
                            else:
                                    return CheckResult.FAILED
                        else:
                                return CheckResult.FAILED
                    else:
                          return CheckResult.FAILED
                else:   
                       return CheckResult.SKIPPED
            else: 
                 return CheckResult.FAILED
        else:
            return CheckResult.FAILED
  
check = FSXFileSystemAdministrator()
