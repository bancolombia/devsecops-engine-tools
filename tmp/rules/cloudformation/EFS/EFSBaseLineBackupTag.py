from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck

class EFSBaseLineBackupTag(BaseResourceCheck):
    def __init__(self):
        name = "Ensure EFS has base line backup tag"
        id = "CKV_AWS_203"
        supported_resources = ['AWS::EFS::FileSystem']
        categories = [CheckCategories.APPLICATION_SECURITY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        contbkm = 0
        contbkd = 0
        if 'Properties' in conf.keys():
            if 'FileSystemTags' in conf['Properties'].keys():
                if isinstance(conf['Properties']['FileSystemTags'], list):
                    for item in conf['Properties']['FileSystemTags']:
                        if 'Key' in item.keys() and 'Value' in item.keys():
                            if item['Key'] == "bancolombia:bkmensual":
                                contbkm = contbkm + 1
                            elif item['Key'] == "bancolombia:bkdiario":
                                contbkd = contbkd + 1
                if contbkm != 0 or contbkd != 0:
                    return CheckResult.PASSED
                else:
                    return CheckResult.FAILED
        return CheckResult.FAILED

check = EFSBaseLineBackupTag()