from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck

class EFSBackUpPolicy(BaseResourceCheck):
    def __init__(self):
        name = "Ensure EFS Backup parameter is desabled"
        id = "CKV_AWS_404"
        supported_resources = ['AWS::EFS::FileSystem']
        categories = [CheckCategories.APPLICATION_SECURITY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if 'Properties' in conf.keys():
            if 'BackupPolicy' in conf['Properties'].keys():
                if 'Status' in conf['Properties']['BackupPolicy'].keys():
                    if conf['Properties']['BackupPolicy']['Status'] == "ENABLED":
                        return CheckResult.FAILED
        return CheckResult.PASSED

check = EFSBackUpPolicy()