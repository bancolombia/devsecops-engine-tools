from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck


class NeptuneMinorVersion(BaseResourceCheck):
    def __init__(self):
        name = "Ensure Minor version for Neptune"
        id = "CKV_AWS_377"
        supported_resources = ['AWS::Neptune::DBInstance']
        categories = [CheckCategories.BACKUP_AND_RECOVERY]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if 'Properties' in conf.keys():
            if 'AutoMinorVersionUpgrade' in conf['Properties'].keys() and str(conf['Properties']['AutoMinorVersionUpgrade']) == "True":
                return CheckResult.PASSED
            return CheckResult.FAILED


check = NeptuneMinorVersion()
