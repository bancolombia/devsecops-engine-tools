from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_value_check import BaseResourceCheck


class KMSDeletionProtection(BaseResourceCheck):
    def __init__(self):
        name = "Ensure KMS deletion protection pending windows in days"
        id = "CKV_AWS_293"
        supported_resources = ['AWS::KMS::Key']
        categories = [CheckCategories.BACKUP_AND_RECOVERY]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if 'Properties' in conf.keys():
            if 'PendingWindowInDays' not in conf['Properties'].keys():
                return CheckResult.UNKNOWN
            else:
                if conf['Properties']['PendingWindowInDays'] in ["30",30]:
                    return CheckResult.PASSED
        return CheckResult.FAILED


check = KMSDeletionProtection()
